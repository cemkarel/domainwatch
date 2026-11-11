import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkDomain, checkTls } from '../src/checks.ts';

test('RDAP distinguishes unsupported TLDs from bootstrap failures and tries a registry fallback', async t => {
  assert.deepEqual(await checkDomain('example.constructor', new Map()), { status: 'unsupported', expiry: null });
  assert.deepEqual(await checkDomain('example.constructor', null), { status: 'bootstrap_unavailable', expiry: null });
  const called: string[] = [];
  t.mock.method(globalThis, 'fetch', async (url: URL) => {
    called.push(url.href);
    if (called.length === 1) return new Response(null, { status: 503 });
    return Response.json({ objectClassName: 'domain', events: [] });
  });
  assert.deepEqual(await checkDomain('example.com', new Map([['com', ['https://rdap.example.com/']]])),
    { status: 'no_expiration', expiry: null });
  assert.deepEqual(called, ['https://rdap.example.com/domain/example.com', 'https://rdap.verisign.com/com/v1/domain/example.com']);
});

test('scanner adapter reports only the matching hostname and preserves untrusted certificate status', async t => {
  const expiry = '2027-02-01T00:00:00.000Z';
  let hostname = 'api.example.com';
  t.mock.method(globalThis, 'fetch', async (url: URL, init: RequestInit) => {
    assert.equal(url.href, 'https://scanner.example.com/check');
    assert.equal(init.redirect, 'manual');
    assert.deepEqual(JSON.parse(String(init.body)), { hostname: 'api.example.com' });
    return Response.json({ hostname, status: 'tls_untrusted', expiry });
  });
  const config = { SCANNER_URL: 'https://scanner.example.com/check', SCANNER_TOKEN: 'test-only-token' };
  assert.deepEqual(await checkTls('api.example.com', config), { status: 'tls_untrusted', expiry });
  hostname = 'other.example.com';
  assert.deepEqual(await checkTls('api.example.com', config), { status: 'scanner_error', expiry: null });
});
