import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { test } from 'node:test';
import worker from '../src/index.ts';
import { day, hash } from '../src/core.ts';
import type { Env } from '../src/env.ts';
import { scheduled } from '../src/jobs.ts';

function fixture() {
  const sql = new DatabaseSync(':memory:');
  sql.exec(readFileSync(new URL('../migrations/0001_init.sql', import.meta.url), 'utf8'));
  function prepare(query: string, params: SQLInputValue[] = []) {
    return {
      bind: (...args: SQLInputValue[]) => prepare(query, args),
      first: async () => sql.prepare(query).get(...params) ?? null,
      all: async () => ({ results: sql.prepare(query).all(...params) }),
      run: async () => ({ meta: sql.prepare(query).run(...params) })
    };
  }
  const limit = async () => ({ success: true });
  const env = {
    DB: {
      prepare,
      batch: async (queries: ReturnType<typeof prepare>[]) => {
        sql.exec('BEGIN');
        try {
          const result = await Promise.all(queries.map(query => query.run()));
          sql.exec('COMMIT');
          return result;
        } catch (error) {
          sql.exec('ROLLBACK');
          throw error;
        }
      }
    },
    APP_ORIGIN: 'https://domainwatch.example',
    WEBHOOK_KEY: btoa('a'.repeat(32)),
    WRITE_LIMIT: { limit }, TEST_LIMIT: { limit }
  } as unknown as Env;
  const alice = 'a'.repeat(64);
  const bob = 'b'.repeat(64);
  async function seed() {
    for (const [id, token] of [['1', alice], ['2', bob]]) {
      sql.prepare('INSERT INTO users VALUES (?, ?)').run(id, 'user' + id);
      sql.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run(await hash(token), id, Date.now() + day);
    }
  }
  function request(path: string, method = 'GET', token = alice, data?: unknown, origin = env.APP_ORIGIN) {
    return worker.fetch(new Request(env.APP_ORIGIN + '/api' + path, {
      method, headers: { Origin: origin!, Cookie: 'dw_session=' + token, 'Content-Type': 'application/json' },
      body: data === undefined ? undefined : JSON.stringify(data)
    }), env);
  }
  return { sql, env, seed, request, alice, bob };
}

const webhook = 'https://hooks.slack.com/services/TTEST/BTEST/0123456789abcdef';

test('API enforces session, tenant isolation and same-origin mutations, and masks encrypted settings', async t => {
  const f = fixture();
  t.after(() => f.sql.close());
  await f.seed();
  assert.equal((await f.request('/targets', 'GET', '')).status, 401);
  assert.equal((await f.request('/targets', 'POST', f.alice, { hostname: 'example.com' }, 'https://elsewhere.example')).status, 403);
  const created = await f.request('/targets', 'POST', f.alice, { hostname: 'api.example.com' });
  assert.equal(created.status, 201);
  const { id } = await created.json() as { id: string };
  assert.deepEqual(await (await f.request('/targets', 'GET', f.bob)).json(), []);
  assert.equal((await f.request('/targets/' + id, 'DELETE', f.bob)).status, 404);
  assert.equal((await f.request('/settings/slack', 'PUT', f.alice, { url: webhook, enabled: false, thresholds: [7] })).status, 200);
  const settings = await (await f.request('/settings/slack')).text();
  assert.ok(settings.includes('••••') && !settings.includes(webhook));
  assert.ok(!JSON.stringify(f.sql.prepare('SELECT * FROM notifications').get()).includes(webhook));
  assert.equal((await f.request('/settings/slack/test', 'POST', f.bob)).status, 400);

  t.mock.method(globalThis, 'fetch', async (url: string, init: RequestInit) => {
    assert.equal(url, webhook);
    assert.equal(init.method, 'POST');
    assert.equal(init.redirect, 'manual');
    assert.match(String(init.body), /Test message/);
    return new Response('ok');
  });
  assert.equal((await f.request('/settings/slack/test', 'POST')).status, 200);
});

test('Cron obtains RDAP data, deduplicates alerts and retries temporary Slack failures', async t => {
  const f = fixture();
  t.after(() => f.sql.close());
  await f.seed();
  await f.request('/targets', 'POST', f.alice, { hostname: 'api.example.com' });
  await f.request('/settings/slack', 'PUT', f.alice, { url: webhook, enabled: true, thresholds: [7] });
  const expiry = new Date(Date.now() + 6 * day).toISOString();
  let slackRequests = 0;
  t.mock.method(globalThis, 'fetch', async (url: string | URL) => {
    if (String(url).includes('data.iana.org')) return Response.json({ services: [[['com'], ['https://rdap.example.com/']]] });
    if (String(url) === 'https://rdap.example.com/domain/example.com') {
      return Response.json({ objectClassName: 'domain', events: [{ eventAction: 'expiration', eventDate: expiry }] });
    }
    if (url === webhook) return new Response('ok', { status: ++slackRequests === 1 ? 429 : 200 });
    throw new Error('Unexpected URL ' + url);
  });

  await scheduled(f.env);
  const target = f.sql.prepare('SELECT domain_expiry, tls_status FROM targets').get();
  assert.equal(target?.domain_expiry, expiry);
  assert.equal(target?.tls_status, 'scanner_unconfigured');
  for (let i = 0; i < 2; i++) {
    f.sql.exec('UPDATE targets SET next_check=0; UPDATE alerts SET next_attempt=0;');
    await scheduled(f.env);
  }
  const alerts = f.sql.prepare('SELECT state, attempts FROM alerts').all();
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].state, 'sent');
  assert.equal(alerts[0].attempts, 2);
  assert.equal(slackRequests, 2);
  assert.deepEqual(await (await f.request('/alerts', 'GET', f.bob)).json(), []);
});
