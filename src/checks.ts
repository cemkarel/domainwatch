import { boundedJson } from './network.ts';

export interface Check {
  status: string;
  expiry: string | null;
}

export interface ScannerConfig {
  SCANNER_URL?: string;
  SCANNER_TOKEN?: string;
  APP_ORIGIN?: string;
}

const fallback = new Map([
  ['com', 'https://rdap.verisign.com/com/v1/'],
  ['net', 'https://rdap.verisign.com/net/v1/'],
  ['org', 'https://rdap.publicinterestregistry.org/rdap/']
]);

export async function rdapBootstrap(): Promise<Map<string, string[]> | null> {
  try {
    const response = await fetch('https://data.iana.org/rdap/dns.json', {
      redirect: 'manual', signal: AbortSignal.timeout(6000),
      cf: { cacheEverything: true, cacheTtl: 86_400 }
    });
    if (!response.ok) {
      await response.body?.cancel();
      return null;
    }
    const data = await boundedJson(response, 256_000) as { services: [string[], string[]][] };
    return new Map(data.services.flatMap(([tlds, endpoints]) =>
      tlds.map(tld => [tld, endpoints] as const)));
  } catch {
    return null;
  }
}

function rdapEndpoint(base: string, domain: string) {
  try {
    const url = new URL(base);
    if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash
      || !/^[a-z0-9.-]+\.[a-z][a-z0-9-]+$/i.test(url.hostname)) return null;
    url.pathname = url.pathname.replace(/\/?$/, '/') + 'domain/' + domain;
    return url;
  } catch {
    return null;
  }
}

export function expiryDate(value: unknown) {
  if (typeof value !== 'string') return null;
  const date = Date.parse(value);
  return Number.isFinite(date) ? new Date(date).toISOString() : null;
}

export async function checkDomain(domain: string, bootstrap: Map<string, string[]> | null): Promise<Check> {
  const tld = domain.split('.').at(-1)!;
  const registry = fallback.get(tld);
  const bases = [...(bootstrap?.get(tld) ?? [])];
  if (registry) bases.push(registry);
  const urls = [...new Set(bases)]
    .map(base => rdapEndpoint(base, domain)).filter(url => url !== null).slice(0, 3);
  if (!urls.length) return { status: bootstrap ? 'unsupported' : 'bootstrap_unavailable', expiry: null };

  let notFound = false;
  let noExpiry = false;
  for (const url of urls) {
    try {
      const response = await fetch(url, {
        redirect: 'manual', signal: AbortSignal.timeout(7000),
        headers: { Accept: 'application/rdap+json, application/json' }
      });
      if (!response.ok) {
        await response.body?.cancel();
        if (response.status === 404) notFound = true;
        continue;
      }
      const data = await boundedJson(response, 512_000) as {
        objectClassName?: string;
        events?: { eventAction: string; eventDate: string }[];
      };
      if (data.objectClassName !== 'domain') continue;
      const expiry = data.events?.filter(event => event.eventAction === 'expiration')
        .map(event => expiryDate(event.eventDate)).find(date => date !== null);
      if (expiry) return { status: 'ok', expiry };
      noExpiry = true;
    } catch {
      // Try the next registry endpoint.
    }
  }
  return { status: noExpiry ? 'no_expiration' : notFound ? 'not_found' : 'rdap_error', expiry: null };
}

export async function checkTls(hostname: string, env: ScannerConfig): Promise<Check> {
  if (!env.SCANNER_URL || !env.SCANNER_TOKEN) return { status: 'scanner_unconfigured', expiry: null };
  try {
    const url = new URL(env.SCANNER_URL);
    const local = env.APP_ORIGIN === 'http://localhost:8787' &&
      url.protocol === 'http:' && url.hostname === '127.0.0.1';
    if ((!local && url.protocol !== 'https:') || url.username || url.password || url.search || url.hash) {
      return { status: 'scanner_configuration_error', expiry: null };
    }
    const response = await fetch(url, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(10_000),
      headers: { Authorization: 'Bearer ' + env.SCANNER_TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname })
    });
    if (!response.ok) {
      await response.body?.cancel();
      return { status: 'scanner_error', expiry: null };
    }
    const data = await boundedJson(response, 1024) as { hostname: string; status: string; expiry?: string };
    if (data.hostname === hostname) {
      const expiry = expiryDate(data.expiry);
      if ((data.status === 'ok' || data.status === 'tls_untrusted') && expiry) return { status: data.status, expiry };
      if (data.status === 'no_public_address' || data.status === 'tls_unreachable') {
        return { status: data.status, expiry: null };
      }
    }
  } catch {
    // Report the configured adapter as unavailable.
  }
  return { status: 'scanner_error', expiry: null };
}
