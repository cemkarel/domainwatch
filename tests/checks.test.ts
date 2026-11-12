import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkDomain } from '../src/checks.ts';
import { tlsChecks } from '../src/tls.ts';

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

test('TLS checks reject a host with non-public DNS answers before launching a browser', async t => {
  t.mock.method(globalThis, 'fetch', async (url: URL, init: RequestInit) => {
    assert.equal(url.hostname, 'cloudflare-dns.com');
    assert.equal(init.redirect, 'manual');
    assert.equal(url.searchParams.get('name'), 'api.example.com');
    const ipv4 = url.searchParams.get('type') === 'A';
    return Response.json({ Status: 0, Answer: [{ type: ipv4 ? 1 : 28, data: ipv4 ? '8.8.8.8' : '::1' }] });
  });
  const checks = tlsChecks({ fetch: async () => { throw new Error('Unexpected browser launch'); } }, ['api.example.com']);
  assert.deepEqual(await checks.check('api.example.com'), { status: 'no_public_address', expiry: null });
  await checks.close();
});
