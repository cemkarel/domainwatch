import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { test } from 'node:test';
import { rootCertificates } from 'node:tls';
import puppeteer, { type Browser } from '@cloudflare/puppeteer';
import { checkDomain, parseTrabisWhois } from '../src/checks.ts';
import { tlsChecks } from '../src/tls.ts';

test('RDAP distinguishes unsupported TLDs from bootstrap failures and tries a registry fallback', async t => {
  assert.deepEqual(await checkDomain('example.constructor', async () => new Map()), { status: 'unsupported', expiry: null });
  assert.deepEqual(await checkDomain('example.constructor', async () => null), { status: 'bootstrap_unavailable', expiry: null });
  const called: string[] = [];
  t.mock.method(globalThis, 'fetch', async (url: URL) => {
    called.push(url.href);
    if (called.length === 1) return new Response(null, { status: 503 });
    return Response.json({ objectClassName: 'domain', events: [] });
  });
  assert.deepEqual(await checkDomain('example.com', async () => new Map([['com', ['https://rdap.example.com/']]])),
    { status: 'no_expiration', expiry: null });
  assert.deepEqual(called, ['https://rdap.example.com/domain/example.com', 'https://rdap.verisign.com/com/v1/domain/example.com']);
});

test('TRABİS WHOIS reads a suspended registration and rejects a wrong or invalid record', () => {
  const record = '** Domain Name: unitedracing.tr\r\nDomain Status: Suspended\r\nExpires on..............: 2026-Nov-10.\r\n';
  assert.deepEqual(parseTrabisWhois('unitedracing.tr', record), { status: 'ok', expiry: '2026-11-10T00:00:00.000Z' });
  assert.deepEqual(parseTrabisWhois('example.com.tr', record.replace('unitedracing.tr', 'example.com.tr')),
    { status: 'ok', expiry: '2026-11-10T00:00:00.000Z' });
  assert.deepEqual(parseTrabisWhois('unitedracing.tr', 'No match found for unitedracing.tr\r\n'),
    { status: 'not_found', expiry: null });
  assert.deepEqual(parseTrabisWhois('unitedracing.tr', '** Domain Name: unitedracing.tr\n'),
    { status: 'no_expiration', expiry: null });
  assert.deepEqual(parseTrabisWhois('other.tr', record), { status: 'whois_error', expiry: null });
  assert.deepEqual(parseTrabisWhois('unitedracing.tr', record.replace('Nov-10', 'Feb-30')),
    { status: 'whois_error', expiry: null });
});

test('The .io registry fallback reads the domain expiry when IANA has no entry', async t => {
  const fetch = t.mock.method(globalThis, 'fetch', async (url: URL) => {
    assert.equal(url.href, 'https://rdap.identitydigital.services/rdap/domain/anbean.io');
    return Response.json({ objectClassName: 'domain', events: [
      { eventAction: 'registration', eventDate: '2026-03-21T09:04:51.32Z' },
      { eventAction: 'expiration', eventDate: '2036-03-21T09:04:51.32Z' }
    ] });
  });
  assert.deepEqual(await checkDomain('anbean.io', async () => new Map()),
    { status: 'ok', expiry: '2036-03-21T09:04:51.320Z' });
  assert.equal(fetch.mock.callCount(), 1);
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

test('TLS checks can read the leaf certificate when the HTTP event omits its expiry', async t => {
  const certificate = new X509Certificate(rootCertificates[0]);
  const origin = 'https://api.example.com';
  let recovered = true;
  let peer = '8.8.8.8';
  let sanList: string[] | undefined;
  const browserExpiry = Date.parse('2030-02-01T00:00:00Z') / 1000;
  let onResponse: (event: { response: {
    url: string; remoteIPAddress: string; securityDetails?: { validTo: number; sanList: string[] };
  } }) => void;
  const page = {
    setJavaScriptEnabled: async () => {},
    setCacheEnabled: async () => {},
    setRequestInterception: async () => {},
    on() {},
    async createCDPSession() {
      return {
        async send(command: string, params?: { origin: string }) {
          if (command === 'Network.enable') return;
          assert.equal(command, 'Network.getCertificate');
          assert.equal(params?.origin, origin);
          return { tableNames: recovered ? [certificate.raw.toString('base64')] : [] };
        },
        on(event: string, listener: typeof onResponse) {
          if (event === 'Network.responseReceived') onResponse = listener;
        },
        detach: async () => {}
      };
    },
    async goto(url: string) {
      onResponse({ response: { url, remoteIPAddress: peer,
        securityDetails: sanList && { validTo: browserExpiry, sanList } } });
    },
    close: async () => {}
  };
  t.mock.method(puppeteer, 'launch', async () => ({ newPage: async () => page, close: async () => {} }) as unknown as Browser);
  t.mock.method(globalThis, 'fetch', async (url: URL) => Response.json({
    Status: 0, Answer: url.searchParams.get('type') === 'A' ? [{ type: 1, data: '8.8.8.8' }] : []
  }));
  const checks = tlsChecks({ fetch }, ['api.example.com']);
  try {
    assert.deepEqual(await checks.check('api.example.com'), {
      status: 'tls_untrusted', expiry: new Date(certificate.validTo).toISOString()
    });
    recovered = false;
    assert.deepEqual(await checks.check('api.example.com'), { status: 'tls_certificate_unavailable', expiry: null });

    peer = '127.0.0.1';
    recovered = true;
    sanList = ['other.example.com'];
    assert.deepEqual(await checks.check('api.example.com'), { status: 'tls_certificate_unavailable', expiry: null });
    sanList = ['*.example.com'];
    assert.deepEqual(await checks.check('api.example.com'), { status: 'ok', expiry: '2030-02-01T00:00:00.000Z' });
  } finally {
    await checks.close();
  }
});
