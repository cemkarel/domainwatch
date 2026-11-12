import { Buffer } from 'node:buffer';
import { X509Certificate } from 'node:crypto';
import puppeteer, { type Browser, type BrowserWorker, type Page } from '@cloudflare/puppeteer';
import ipaddr from 'ipaddr.js';
import type { Check } from './checks.ts';
import { normalizeHost } from './core.ts';
import { boundedJson } from './network.ts';

function isPublicAddress(address: string) {
  return ipaddr.isValid(address) && ipaddr.process(address).range() === 'unicast';
}

function matchesCertificateName(hostname: string, name: string) {
  const san = name.toLowerCase();
  const dot = hostname.indexOf('.');
  return san === hostname || (dot !== -1 && san === '*.' + hostname.slice(dot + 1));
}

async function resolveAddresses(hostname: string, type: 'A' | 'AAAA') {
  const url = new URL('https://cloudflare-dns.com/dns-query');
  url.search = new URLSearchParams({ name: hostname, type }).toString();
  const response = await fetch(url, {
    headers: { Accept: 'application/dns-json' }, redirect: 'manual', signal: AbortSignal.timeout(4000)
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error('DNS lookup failed');
  }
  const data = await boundedJson(response, 16_384) as { Status: number; Answer?: { type: number; data: string }[] };
  if (data.Status !== 0 && data.Status !== 3) throw new Error('DNS lookup failed');
  return (data.Answer ?? []).filter(answer => answer.type === (type === 'A' ? 1 : 28)).map(answer => answer.data);
}

async function scanPage(page: Page, hostname: string): Promise<Check> {
  const url = 'https://' + hostname + '/';
  let allowRequest = false;
  let method: 'HEAD' | 'GET' = 'GET';
  let expiry: string | null = null;
  let receivedResponse = false;
  let peerNeedsProof = false;
  await page.setJavaScriptEnabled(false);
  await page.setCacheEnabled(false);
  await page.setRequestInterception(true);
  page.on('request', request => {
    if (allowRequest && request.isNavigationRequest() && request.url() === url) {
      allowRequest = false;
      return method === 'GET' ? request.continue() : request.continue({ method });
    }
    return request.abort();
  });

  const cdp = await page.createCDPSession();
  let untrusted = false;
  try {
    await cdp.send('Network.enable');
    const readExpiry = (response: {
      url: string;
      remoteIPAddress?: string;
      securityDetails?: { validTo: number; sanList?: string[] };
    }) => {
      if (response.url !== url) return;
      receivedResponse = true;
      const details = response.securityDetails;
      // The DevTools peer can be a browser proxy. Require hostname evidence for that response.
      if (response.remoteIPAddress && !isPublicAddress(response.remoteIPAddress)) {
        peerNeedsProof = true;
        if (!details?.sanList?.some(name => matchesCertificateName(hostname, name))) return;
      }
      const validTo = details?.validTo;
      if (validTo !== undefined && Number.isFinite(validTo)) expiry = new Date(validTo * 1000).toISOString();
    };
    cdp.on('Network.responseReceived', event => readExpiry(event.response));
    cdp.on('Network.requestWillBeSent', event => {
      if (event.redirectResponse) readExpiry(event.redirectResponse);
    });

    async function navigate(requestMethod: typeof method) {
      method = requestMethod;
      allowRequest = true;
      try {
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 5000 });
        return undefined;
      } catch (error) {
        return error instanceof Error ? /net::ERR_[A-Z_]+/.exec(error.message)?.[0] ?? error.name : undefined;
      }
    }

    let error = await navigate('GET');
    if (!expiry && !error?.startsWith('net::ERR_CERT_')) error = await navigate('HEAD');
    if (!expiry && error?.startsWith('net::ERR_CERT_')) {
      await cdp.send('Security.setIgnoreCertificateErrors', { ignore: true });
      untrusted = true;
      error = await navigate('GET');
      if (!expiry) error = await navigate('HEAD');
    }
    if (!expiry) {
      try {
        const { tableNames: [leaf] } = await cdp.send('Network.getCertificate', { origin: 'https://' + hostname });
        if (leaf) {
          const certificate = new X509Certificate(Buffer.from(leaf, 'base64'));
          const validTo = Date.parse(certificate.validTo);
          const matchesHost = Boolean(certificate.checkHost(hostname));
          if (Number.isFinite(validTo) && (!peerNeedsProof || matchesHost)) {
            expiry = new Date(validTo).toISOString();
            const now = Date.now();
            untrusted ||= validTo <= now || Date.parse(certificate.validFrom) > now || !matchesHost;
          }
        }
      } catch {
        // This optional CDP command may be unavailable on some browser versions.
      }
    }
    if (expiry || untrusted) return { status: untrusted ? 'tls_untrusted' : 'ok', expiry };

    const status = receivedResponse ? 'tls_certificate_unavailable' : 'tls_unreachable';
    console.warn({ event: 'tls_navigation_failed', hostname, status,
      error: peerNeedsProof ? 'browser_peer_without_matching_certificate' : error ?? 'missing_certificate_details' });
    return { status, expiry: null };
  } finally {
    if (untrusted) await cdp.send('Security.setIgnoreCertificateErrors', { ignore: false }).catch(() => {});
    await cdp.detach().catch(() => {});
  }
}

export function tlsChecks(binding: BrowserWorker | undefined, hostnames: string[]) {
  let browser: Promise<Browser> | undefined;
  let closed = false;
  return {
    async check(hostname: string): Promise<Check> {
      if (!binding) return { status: 'scanner_unconfigured', expiry: null };
      if (normalizeHost(hostname)?.hostname !== hostname) return { status: 'no_public_address', expiry: null };
      try {
        const [ipv4, ipv6] = await Promise.all([resolveAddresses(hostname, 'A'), resolveAddresses(hostname, 'AAAA')]);
        const addresses = [...ipv4, ...ipv6];
        if (!addresses.length || !addresses.every(isPublicAddress)) {
          console.warn({ event: 'tls_dns_rejected', hostname, reason: addresses.length ? 'non_public_dns_answer' : 'no_address_records' });
          return { status: 'no_public_address', expiry: null };
        }

        if (closed) return { status: 'scanner_error', expiry: null };
        browser ??= puppeteer.launch(binding, { guardrails: { allowedDomains: [...new Set(hostnames)] } });
        const session = await browser;
        if (closed) return { status: 'scanner_error', expiry: null };
        const page = await session.newPage();
        try {
          return await scanPage(page, hostname);
        } finally {
          await page.close().catch(() => {});
        }
      } catch (error) {
        const detail = String(error).replace(/(?:https?|wss?):\/\/\S+/g, '[url]').slice(0, 240);
        console.warn({ event: 'tls_browser_failure', hostname, error: detail });
        return { status: 'scanner_error', expiry: null };
      }
    },
    async close() {
      closed = true;
      if (browser) await browser.then(session => session.close()).catch(() => {});
    }
  };
}
