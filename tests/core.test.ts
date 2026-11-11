import assert from 'node:assert/strict';
import { test } from 'node:test';
import { day, decryptWebhook, dueThreshold, encryptWebhook, normalizeHost, parseThresholds, webhookUrl } from '../src/core.ts';

test('subdomains retain TLS hostname and use the registrable RDAP domain', () => {
  assert.deepEqual(normalizeHost('API.Example.CO.UK.'), { hostname: 'api.example.co.uk', domain: 'example.co.uk' });
  assert.deepEqual(normalizeHost('bücher.de'), { hostname: 'xn--bcher-kva.de', domain: 'xn--bcher-kva.de' });
  assert.deepEqual(normalizeHost('some.github.io'), { hostname: 'some.github.io', domain: 'github.io' });
  for (const host of ['127.1', '0x7f000001', '[::1]', 'https://example.com', 'a.example.com:443',
    'foo.local', 'a..com', 'foo%2Ecom', 'user@example.com', 'a.com/path']) assert.equal(normalizeHost(host), null, host);
});

test('Slack destinations use the exact public incoming webhook URL format', () => {
  const suffix = '/services/TTEST/BTEST/0123456789abcdef';
  assert.equal(webhookUrl('https://hooks.slack.com' + suffix), 'https://hooks.slack.com' + suffix);
  for (const url of [
    'https://hooks.slack.com.evil.com' + suffix, 'https://hooks.slack.com@evil.com' + suffix,
    'http://hooks.slack.com' + suffix, 'https://hooks.slack.com:443' + suffix,
    'https://hooks.slack.com' + suffix + '?x=1', 'https://hooks.slack.com' + suffix + '/extra'
  ]) assert.equal(webhookUrl(url), null);
});

test('thresholds select the closest applicable window', () => {
  const values = parseThresholds([30, 1, 14, 7, 3]);
  assert.deepEqual(values, [1, 3, 7, 14, 30]);
  assert.equal(parseThresholds([7, 7]), null);
  assert.equal(parseThresholds([6]), null);
  const expiry = '2027-01-01T00:00:00.000Z';
  const instant = Date.parse(expiry);
  assert.equal(dueThreshold(expiry, values!, instant - 8 * day), 14);
  assert.equal(dueThreshold(expiry, values!, instant - day), 1);
  assert.equal(dueThreshold(expiry, values!, instant), undefined);
  assert.equal(dueThreshold(expiry, values!, instant - 31 * day), undefined);
});

test('AES-GCM ciphertext is randomized and bound to its tenant', async () => {
  const secret = btoa('a'.repeat(32));
  const value = 'https://hooks.slack.com/services/TTEST/BTEST/0123456789abcdef';
  const encrypted = await encryptWebhook(value, secret, '42');
  assert.ok(!encrypted.includes(value));
  assert.notEqual(encrypted, await encryptWebhook(value, secret, '42'));
  assert.equal(await decryptWebhook(encrypted, secret, '42'), value);
  await assert.rejects(decryptWebhook(encrypted, secret, '43'));
});
