import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { test } from 'node:test';
import worker from '../src/index.ts';
import { day, encryptWebhook } from '../src/core.ts';
import type { Env } from '../src/env.ts';
import { scheduled } from '../src/jobs.ts';

function fixture() {
  const sql = new DatabaseSync(':memory:');
  sql.exec(readFileSync(new URL('../migrations/0001_init.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0002_shared_workspace.sql', import.meta.url), 'utf8'));
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
    WEBHOOK_KEY: btoa('a'.repeat(32)),
    WRITE_LIMIT: { limit }, TEST_LIMIT: { limit }
  } as unknown as Env;
  const baseUrl = 'https://domainwatch.example';
  function request(path: string, method = 'GET', data?: unknown, origin: string | null = baseUrl) {
    const headers = new Headers({ 'Content-Type': 'application/json' });
    if (origin !== null) headers.set('Origin', origin);
    return worker.fetch(new Request(baseUrl + '/api' + path, {
      method, headers,
      body: data === undefined ? undefined : JSON.stringify(data)
    }), env);
  }
  function seedLegacyTarget() {
    sql.prepare("INSERT INTO users VALUES ('12345', 'legacy')").run();
    sql.prepare("INSERT INTO targets (id,user_id,hostname,domain) VALUES ('legacy-id','12345','example.org','example.org')").run();
  }
  return { sql, env, request, seedLegacyTarget };
}

const webhook = 'https://hooks.slack.com/services/TTEST/BTEST/0123456789abcdef';

test('Public API uses a shared workspace, enforces same-origin mutations and masks encrypted settings', async t => {
  const f = fixture();
  t.after(() => f.sql.close());
  f.seedLegacyTarget();
  const empty = await f.request('/targets', 'GET', undefined, null);
  assert.equal(empty.status, 200);
  assert.deepEqual(await empty.json(), []);
  assert.equal((await f.request('/targets', 'POST', { hostname: 'example.com' }, 'https://elsewhere.example')).status, 403);
  assert.equal((await f.request('/targets', 'POST', { hostname: 'example.com' }, null)).status, 403);
  const created = await f.request('/targets', 'POST', { hostname: 'api.example.com' });
  assert.equal(created.status, 201);
  const { id } = await created.json() as { id: string };
  const targets = await (await f.request('/targets')).json() as { id: string }[];
  assert.deepEqual(targets.map(target => target.id), [id]);
  assert.equal((await f.request('/targets/legacy-id', 'DELETE')).status, 404);
  assert.equal((await f.request('/targets/' + id, 'DELETE')).status, 200);
  assert.equal((await f.request('/settings/slack/test', 'POST')).status, 400);
  assert.equal((await f.request('/settings/slack', 'PUT', { url: webhook, enabled: false, thresholds: [7] })).status, 200);
  const settings = await (await f.request('/settings/slack')).text();
  assert.ok(settings.includes('••••') && !settings.includes(webhook));
  assert.ok(!JSON.stringify(f.sql.prepare('SELECT * FROM notifications').get()).includes(webhook));

  t.mock.method(globalThis, 'fetch', async (url: string, init: RequestInit) => {
    assert.equal(url, webhook);
    assert.equal(init.method, 'POST');
    assert.equal(init.redirect, 'manual');
    assert.match(String(init.body), /Test message/);
    return new Response('ok');
  });
  assert.equal((await f.request('/settings/slack/test', 'POST')).status, 200);
});

test('A configured workspace owner reuses legacy targets and encrypted Slack settings', async t => {
  const f = fixture();
  t.after(() => f.sql.close());
  f.seedLegacyTarget();
  const encrypted = await encryptWebhook(webhook, f.env.WEBHOOK_KEY!, '12345');
  f.sql.prepare("INSERT INTO notifications VALUES ('12345', ?, 1, '[7]', 'legacy-version')").run(encrypted);
  f.env.WORKSPACE_OWNER_ID = '12345';

  const targets = await (await f.request('/targets')).json() as { id: string }[];
  assert.deepEqual(targets.map(target => target.id), ['legacy-id']);
  t.mock.method(globalThis, 'fetch', async (url: string) => {
    assert.equal(url, webhook);
    return new Response('ok');
  });
  assert.equal((await f.request('/settings/slack/test', 'POST')).status, 200);
});

test('Cron obtains RDAP data, deduplicates alerts and retries temporary Slack failures', async t => {
  const f = fixture();
  t.after(() => f.sql.close());
  f.seedLegacyTarget();
  await f.request('/targets', 'POST', { hostname: 'api.example.com' });
  await f.request('/settings/slack', 'PUT', { url: webhook, enabled: true, thresholds: [7] });
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
  const target = f.sql.prepare("SELECT domain_expiry, tls_status FROM targets WHERE user_id='shared'").get();
  assert.equal(target?.domain_expiry, expiry);
  assert.equal(target?.tls_status, 'scanner_unconfigured');
  assert.equal(f.sql.prepare("SELECT checked_at FROM targets WHERE id='legacy-id'").get()?.checked_at, null);
  for (let i = 0; i < 2; i++) {
    f.sql.exec('UPDATE targets SET next_check=0; UPDATE alerts SET next_attempt=0;');
    await scheduled(f.env);
  }
  const alerts = f.sql.prepare('SELECT state, attempts FROM alerts').all();
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].state, 'sent');
  assert.equal(alerts[0].attempts, 2);
  assert.equal(slackRequests, 2);
  const history = await (await f.request('/alerts')).json() as { state: string }[];
  assert.deepEqual(history.map(alert => alert.state), ['sent']);
});
