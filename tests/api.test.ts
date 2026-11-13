import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { test } from 'node:test';
import puppeteer, {
  type Browser, type BrowserWorker, type HTTPRequest, type WorkersLaunchOptions
} from '@cloudflare/puppeteer';
import worker from '../src/index.ts';
import { day, encryptWebhook } from '../src/core.ts';
import type { Env } from '../src/env.ts';
import { scheduled } from '../src/jobs.ts';

const initialPassword = 'test-only-admin-password';

function fixture() {
  const sql = new DatabaseSync(':memory:');
  sql.exec(readFileSync(new URL('../migrations/0001_init.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0002_shared_workspace.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0003_admin_auth.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0004_browser_tls.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0005_retry_unreachable_tls.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0006_webhook_key_deploy_lock.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0007_retry_tls_certificate_checks.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0008_retry_tls_dns_status.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0009_retry_pending_checks.sql', import.meta.url), 'utf8'));
  sql.exec(readFileSync(new URL('../migrations/0010_retry_tls_with_certificate_api.sql', import.meta.url), 'utf8'));
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
    ADMIN_PASSWORD: initialPassword,
    WEBHOOK_KEY: btoa('a'.repeat(32)),
    LOGIN_LIMIT: { limit }, WRITE_LIMIT: { limit }, TEST_LIMIT: { limit }
  } as unknown as Env;
  const baseUrl = 'https://domainwatch.example';
  const pending: Promise<unknown>[] = [];
  const ctx = { waitUntil(task: Promise<unknown>) { pending.push(task); } } as ExecutionContext;
  let sessionCookie = '';
  function request(path: string, method = 'GET', data?: unknown, origin: string | null = baseUrl, cookie = sessionCookie) {
    const headers = new Headers({ 'Content-Type': 'application/json' });
    if (origin !== null) headers.set('Origin', origin);
    if (cookie) headers.set('Cookie', cookie);
    return worker.fetch(new Request(baseUrl + '/api' + path, {
      method, headers,
      body: data === undefined ? undefined : JSON.stringify(data)
    }), env, ctx);
  }
  async function login(password = initialPassword) {
    const response = await request('/auth/login', 'POST', { username: 'admin', password });
    if (response.ok) sessionCookie = response.headers.get('Set-Cookie')!.split(';')[0];
    return response;
  }
  function seedLegacyTarget() {
    sql.prepare("INSERT INTO users VALUES ('12345', 'legacy')").run();
    sql.prepare("INSERT INTO targets (id,user_id,hostname,domain) VALUES ('legacy-id','12345','example.org','example.org')").run();
  }
  return { sql, env, request, login, seedLegacyTarget, completeChecks: () => Promise.all(pending.splice(0)) };
}

const webhook = 'https://hooks.slack.com/services/TTEST/BTEST/0123456789abcdef';

test('Admin login gates the API and password changes invalidate all existing sessions', async t => {
  const f = fixture();
  t.after(() => f.sql.close());
  for (const path of ['/targets', '/settings/slack', '/alerts', '/auth/session']) {
    assert.equal((await f.request(path)).status, 401);
  }
  assert.equal((await f.request('/auth/login', 'POST', { username: 'admin', password: initialPassword }, 'https://elsewhere.example')).status, 403);
  assert.equal((await f.request('/auth/login', 'POST', { username: 'other', password: initialPassword })).status, 401);
  f.env.ADMIN_PASSWORD = undefined;
  assert.equal((await f.login()).status, 503);
  f.env.ADMIN_PASSWORD = initialPassword;
  assert.equal((await f.login('test-incorrect-password')).status, 401);
  assert.equal(f.sql.prepare('SELECT COUNT(*) AS count FROM admin_credentials').get()?.count, 0);

  const login = await f.login();
  assert.equal(login.status, 200);
  const cookieHeader = login.headers.get('Set-Cookie')!;
  assert.match(cookieHeader, /HttpOnly/i);
  assert.match(cookieHeader, /Secure/i);
  assert.match(cookieHeader, /SameSite=Strict/i);
  const firstCookie = cookieHeader.split(';')[0];
  assert.ok(!JSON.stringify(f.sql.prepare('SELECT * FROM admin_credentials').get()).includes(initialPassword));
  assert.ok(!JSON.stringify(f.sql.prepare('SELECT * FROM admin_sessions').get()).includes(firstCookie.split('=')[1]));
  assert.equal((await f.request('/auth/session')).status, 200);
  assert.equal((await f.login()).status, 200);

  const newPassword = 'test-only-replacement-password';
  assert.equal((await f.request('/auth/password', 'PUT', { currentPassword: initialPassword, newPassword: 'short' })).status, 400);
  assert.equal((await f.request('/auth/password', 'PUT', { currentPassword: newPassword, newPassword })).status, 400);
  assert.equal((await f.request('/auth/password', 'PUT', { currentPassword: initialPassword, newPassword })).status, 200);
  assert.equal((await f.request('/auth/session')).status, 401);
  assert.equal((await f.request('/targets', 'GET', undefined, null, firstCookie)).status, 401);
  assert.equal((await f.login()).status, 401);

  f.env.ADMIN_PASSWORD = undefined;
  assert.equal((await f.login(newPassword)).status, 200);
  assert.equal((await f.request('/auth/logout', 'POST')).status, 200);
  assert.equal((await f.request('/auth/session')).status, 401);
});

test('The watchlist accepts more than 400 addresses and rejects duplicates', async t => {
  const f = fixture();
  t.after(() => f.sql.close());
  assert.equal((await f.login()).status, 200);
  const insert = f.sql.prepare("INSERT INTO targets (id,user_id,hostname,domain) VALUES (?,'shared',?,?)");
  for (let i = 0; i < 400; i++) {
    const hostname = `site-${i}.example.com`;
    insert.run(hostname, hostname, 'example.com');
  }
  t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 503 }));

  const hostname = 'site-400.example.com';
  assert.equal((await f.request('/targets', 'POST', { hostname })).status, 201);
  await f.completeChecks();
  const duplicate = await f.request('/targets', 'POST', { hostname });
  assert.equal(duplicate.status, 409);
  assert.deepEqual(await duplicate.json(), { error: 'duplicate_hostname' });
  const targets = await (await f.request('/targets')).json() as { hostname: string }[];
  assert.equal(targets.length, 401);
  assert.ok(targets.some(target => target.hostname === hostname));
});

test('The admin API tests unsaved Slack URLs and only returns decrypted settings to the admin', async t => {
  const f = fixture();
  t.after(() => f.sql.close());
  assert.equal((await f.login()).status, 200);
  f.seedLegacyTarget();
  t.mock.method(globalThis, 'fetch', async (url: string | URL, init: RequestInit) => {
    if (url !== webhook) return new Response(null, { status: 503 });
    assert.equal(init.method, 'POST');
    assert.equal(init.redirect, 'manual');
    assert.match(String(init.body), /Test message/);
    return new Response('ok');
  });
  const empty = await f.request('/targets', 'GET', undefined, null);
  assert.equal(empty.status, 200);
  assert.deepEqual(await empty.json(), []);
  assert.equal((await f.request('/targets', 'POST', { hostname: 'example.com' }, 'https://elsewhere.example')).status, 403);
  assert.equal((await f.request('/targets', 'POST', { hostname: 'example.com' }, null)).status, 403);
  const created = await f.request('/targets', 'POST', { hostname: 'api.example.com' });
  assert.equal(created.status, 201);
  await f.completeChecks();
  const { id } = await created.json() as { id: string };
  const targets = await (await f.request('/targets')).json() as { id: string }[];
  assert.deepEqual(targets.map(target => target.id), [id]);
  assert.equal((await f.request('/targets/legacy-id', 'DELETE')).status, 404);
  assert.equal((await f.request('/targets/' + id, 'DELETE')).status, 200);
  assert.equal((await f.request('/settings/slack/test', 'POST')).status, 400);
  const key = f.env.WEBHOOK_KEY;
  f.env.WEBHOOK_KEY = undefined;
  assert.equal((await f.request('/settings/slack/test', 'POST', { url: 'https://example.com' })).status, 400);
  assert.equal((await f.request('/settings/slack/test', 'POST', { url: webhook })).status, 200);
  assert.equal(f.sql.prepare('SELECT COUNT(*) AS count FROM notifications').get()?.count, 0);
  f.env.WEBHOOK_KEY = key;
  assert.equal((await f.request('/settings/slack', 'PUT', { url: webhook, enabled: false, thresholds: [7] })).status, 200);
  const response = await f.request('/settings/slack');
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.equal((await response.json() as { url: string }).url, webhook);
  assert.equal((await f.request('/settings/slack', 'GET', undefined, null, '')).status, 401);
  assert.ok(!JSON.stringify(f.sql.prepare('SELECT * FROM notifications').get()).includes(webhook));

  assert.equal((await f.request('/settings/slack/test', 'POST')).status, 200);
});

test('Adding a target returns before TLS and publishes RDAP while the TLS check is still running', async t => {
  const f = fixture();
  let releaseTls!: () => void;
  const tlsGate = new Promise<void>(resolve => { releaseTls = resolve; });
  t.after(async () => {
    releaseTls();
    await f.completeChecks();
    f.sql.close();
  });
  assert.equal((await f.login()).status, 200);
  f.env.TLS_BROWSER = { fetch } as Env['TLS_BROWSER'];
  await f.request('/settings/slack', 'PUT', { url: webhook, enabled: true, thresholds: [7] });
  const domainExpiry = new Date(Date.now() + 6 * day).toISOString();
  const tlsExpiry = new Date(Math.floor((Date.now() + 3 * day) / 1000) * 1000).toISOString();
  let onRequest: (request: HTTPRequest) => Promise<void>;
  let onRedirect: (event: { redirectResponse: { url: string; remoteIPAddress: string; securityDetails: { validTo: number } } }) => void;
  const close = t.mock.fn(async () => {});
  const page = {
    setJavaScriptEnabled: async (enabled: boolean) => assert.equal(enabled, false),
    setCacheEnabled: async (enabled: boolean) => assert.equal(enabled, false),
    setRequestInterception: async (enabled: boolean) => assert.equal(enabled, true),
    on(_event: string, listener: typeof onRequest) {
      onRequest = listener;
    },
    async createCDPSession() {
      return {
        send: async (command: string) => assert.equal(command, 'Network.enable'),
        on(event: string, listener: typeof onRedirect) {
          if (event === 'Network.requestWillBeSent') onRedirect = listener;
        },
        detach: async () => {}
      };
    },
    async goto(url: string) {
      assert.equal(url, 'https://api.example.com/');
      await tlsGate;
      const send = t.mock.fn(async (overrides?: { method: string }) => overrides?.method);
      await onRequest({
        url: () => url,
        isNavigationRequest: () => true,
        continue: send
      } as unknown as HTTPRequest);
      assert.equal(send.mock.callCount(), 1);
      if (!send.mock.calls[0].arguments[0]) throw new Error('net::ERR_CONNECTION_RESET');

      const abort = t.mock.fn(async () => {});
      await onRequest({ url: () => 'https://other.example.com/', isNavigationRequest: () => true, abort } as unknown as HTTPRequest);
      assert.equal(abort.mock.callCount(), 1);
      onRedirect({ redirectResponse: {
        url, remoteIPAddress: '8.8.8.8', securityDetails: { validTo: Date.parse(tlsExpiry) / 1000 }
      } });
      throw new Error('net::ERR_ABORTED');
    },
    close: async () => {}
  };
  const launch = t.mock.method(puppeteer, 'launch', async (binding: BrowserWorker, options?: WorkersLaunchOptions) => {
    assert.equal(binding, f.env.TLS_BROWSER);
    assert.deepEqual(options?.guardrails?.allowedDomains, ['api.example.com']);
    return { newPage: async () => page, close } as unknown as Browser;
  });
  const fetchMock = t.mock.method(globalThis, 'fetch', async (url: string | URL) => {
    if (url === 'https://data.iana.org/rdap/dns.json') {
      return Response.json({ services: [[['com'], ['https://rdap.example.com/']]] });
    }
    if (String(url) === 'https://rdap.example.com/domain/example.com') {
      return Response.json({ objectClassName: 'domain', events: [{ eventAction: 'expiration', eventDate: domainExpiry }] });
    }
    if (url instanceof URL && url.hostname === 'cloudflare-dns.com') {
      assert.equal(url.searchParams.get('name'), 'api.example.com');
      const Answer = url.searchParams.get('type') === 'A' ? [{ type: 1, data: '8.8.8.8' }] : [];
      return Response.json({ Status: 0, Answer });
    }
    if (url instanceof URL && url.hostname === 'api.domainee.dev') return new Response(null, { status: 429 });
    throw new Error('Unexpected URL ' + url);
  });

  const response = await f.request('/targets', 'POST', { hostname: 'api.example.com' });
  assert.equal(response.status, 201);
  const { id, checked } = await response.json() as { id: string; checked: boolean };
  assert.equal(checked, false);
  await new Promise<void>(resolve => setImmediate(resolve));
  const partial = f.sql.prepare('SELECT domain_expiry,tls_status FROM targets WHERE id=?').get(id);
  assert.equal(partial?.domain_expiry, domainExpiry);
  assert.equal(partial?.tls_status, 'pending');
  releaseTls();
  await f.completeChecks();
  const targets = await (await f.request('/targets')).json() as Record<string, unknown>[];
  assert.equal(targets[0].id, id);
  assert.equal(targets[0].domain_expiry, domainExpiry);
  assert.equal(targets[0].tls_expiry, tlsExpiry);
  const timing = f.sql.prepare('SELECT next_check - checked_at AS interval, lease FROM targets WHERE id=?').get(id);
  assert.equal(timing?.interval, day);
  assert.equal(timing?.lease, null);
  const alerts = f.sql.prepare('SELECT kind FROM alerts WHERE target_id=? ORDER BY kind').all(id);
  assert.deepEqual(alerts.map(alert => alert.kind), ['domain', 'tls']);
  assert.equal((await f.request('/targets', 'POST', { hostname: 'api.example.com' })).status, 409);
  assert.equal(fetchMock.mock.callCount(), 5);
  assert.equal(launch.mock.callCount(), 1);
  assert.equal(close.mock.callCount(), 1);
});

test('A configured workspace owner reuses legacy targets and encrypted Slack settings', async t => {
  const f = fixture();
  t.after(() => f.sql.close());
  assert.equal((await f.login()).status, 200);
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
  assert.equal((await f.login()).status, 200);
  f.seedLegacyTarget();
  f.sql.prepare(`
    INSERT INTO targets (id,user_id,hostname,domain,tls_status,next_check)
    VALUES ('pending-id','shared','api.example.com','example.com','no_public_address',?)
  `).run(Date.now() + day);
  f.sql.exec(readFileSync(new URL('../migrations/0008_retry_tls_dns_status.sql', import.meta.url), 'utf8'));
  await f.request('/settings/slack', 'PUT', { url: webhook, enabled: true, thresholds: [7] });
  const expiry = new Date(Date.now() + 6 * day).toISOString();
  let slackRequests = 0;
  let rdapRequests = 0;
  t.mock.method(globalThis, 'fetch', async (url: string | URL) => {
    if (String(url).includes('data.iana.org')) return Response.json({ services: [[['com'], ['https://rdap.example.com/']]] });
    if (String(url) === 'https://rdap.example.com/domain/example.com') {
      rdapRequests++;
      return Response.json({ objectClassName: 'domain', events: [{ eventAction: 'expiration', eventDate: expiry }] });
    }
    if (url instanceof URL && url.hostname === 'cloudflare-dns.com') {
      return Response.json({ Status: 0, Answer: [{ type: 1, data: '8.8.8.8' }] });
    }
    if (url instanceof URL && url.hostname === 'api.domainee.dev') {
      assert.equal(url.searchParams.get('host'), 'api.example.com');
      return Response.json({ ok: true, data: {
        host: 'api.example.com', port: 443, authorized: true, validTo: new Date(Date.now() + 90 * day).toISOString()
      } });
    }
    if (url === webhook) return new Response('ok', { status: ++slackRequests === 1 ? 429 : 200 });
    throw new Error('Unexpected URL ' + url);
  });

  await scheduled(f.env);
  const target = f.sql.prepare("SELECT domain_expiry, tls_status FROM targets WHERE user_id='shared'").get();
  assert.equal(target?.domain_expiry, expiry);
  assert.equal(target?.tls_status, 'ok');
  assert.equal(f.sql.prepare("SELECT checked_at FROM targets WHERE id='legacy-id'").get()?.checked_at, null);
  await scheduled(f.env);
  assert.equal(rdapRequests, 1);
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
