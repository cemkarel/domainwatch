import puppeteer, { type Browser, type BrowserWorker, type Page } from '@cloudflare/puppeteer';
import ipaddr from 'ipaddr.js';
import type { Check } from './checks.ts';
import { normalizeHost } from './core.ts';
import { boundedJson } from './network.ts';

function isPublicAddress(address: string) {
  return ipaddr.isValid(address) && ipaddr.process(address).range() === 'unicast';
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
  let allowRequest = true;
  let expiry: string | null = null;
  await page.setJavaScriptEnabled(false);
  await page.setRequestInterception(true);
  page.on('request', request => {
    if (allowRequest && request.isNavigationRequest() && request.url() === url) {
      allowRequest = false;
      return request.continue({ method: 'HEAD' });
    }
    return request.abort();
  });
  page.on('response', response => {
    if (!response.request().isNavigationRequest() || response.url() !== url) return;
    const address = response.remoteAddress().ip;
    if (address && !isPublicAddress(address)) return;
    const validTo = response.securityDetails()?.validTo();
    if (validTo !== undefined && Number.isFinite(validTo)) expiry = new Date(validTo * 1000).toISOString();
  });

  const navigate = () => page.goto(url, { waitUntil: 'domcontentloaded', timeout: 5000 });
  try {
    await navigate();
  } catch (error) {
    if (expiry) return { status: 'ok', expiry };
    if (!(error instanceof Error) || !/net::ERR_CERT_/.test(error.message)) {
      return { status: 'tls_unreachable', expiry: null };
    }

    const cdp = await page.createCDPSession();
    await cdp.send('Security.setIgnoreCertificateErrors', { ignore: true });
    try {
      allowRequest = true;
      await navigate().catch(() => {});
      return { status: 'tls_untrusted', expiry };
    } finally {
      await cdp.send('Security.setIgnoreCertificateErrors', { ignore: false }).catch(() => {});
      await cdp.detach().catch(() => {});
    }
  }
  return expiry ? { status: 'ok', expiry } : { status: 'tls_unreachable', expiry: null };
}

async function launchBrowser(binding: BrowserWorker, hostnames: string[]) {
  const options = { guardrails: { allowedDomains: [...new Set(hostnames)] } };
  try {
    return await puppeteer.launch(binding, options);
  } catch (error) {
    // The Free plan permits one new session every 20 seconds.
    if (!(error instanceof Error) || !/code: 429:/.test(error.message) || /time limit/i.test(error.message)) throw error;
    await new Promise(resolve => setTimeout(resolve, 20_000));
    return puppeteer.launch(binding, options);
  }
}

export function tlsChecks(binding: BrowserWorker | undefined, hostnames: string[]) {
  let browser: Promise<Browser> | undefined;
  return {
    async check(hostname: string): Promise<Check> {
      if (!binding) return { status: 'scanner_unconfigured', expiry: null };
      if (normalizeHost(hostname)?.hostname !== hostname) return { status: 'no_public_address', expiry: null };
      try {
        const [ipv4, ipv6] = await Promise.all([resolveAddresses(hostname, 'A'), resolveAddresses(hostname, 'AAAA')]);
        const addresses = [...ipv4, ...ipv6];
        if (!addresses.length || !addresses.every(isPublicAddress)) {
          return { status: 'no_public_address', expiry: null };
        }

        browser ??= launchBrowser(binding, hostnames);
        const page = await (await browser).newPage();
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
      if (browser) await browser.then(session => session.close()).catch(() => {});
    }
  };
}
