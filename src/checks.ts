import { normalizeHost } from './core.ts';
import { boundedJson, boundedText } from './network.ts';

export interface Check {
  status: string;
  expiry: string | null;
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

const whoisError: Check = { status: 'whois_error', expiry: null };
const months = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

export function parseTrabisWhois(domain: string, body: string): Check {
  const name = /^\*\* Domain Name:[ \t]*([^\s]+)[ \t]*$/im.exec(body)?.[1]?.toLowerCase();
  if (name !== domain) {
    const missing = /^No match found for[ \t]+([^\s]+)[ \t]*$/im.exec(body)?.[1]?.toLowerCase();
    return !name && missing === domain ? { status: 'not_found', expiry: null } : whoisError;
  }

  const value = /^Expires on\.*:([^\r\n]*)/im.exec(body)?.[1]?.trim();
  if (!value || value === '-') return { status: 'no_expiration', expiry: null };
  const date = /^(\d{4})-([a-z]{3})-(\d{1,2})\.?$/i.exec(value);
  if (!date) return whoisError;
  const month = months.indexOf(date[2].toLowerCase()) + 1;
  const day = `${date[1]}-${String(month).padStart(2, '0')}-${date[3].padStart(2, '0')}`;
  const expiry = month ? expiryDate(day) : null;
  return expiry?.startsWith(day) ? { status: 'ok', expiry } : whoisError;
}

async function checkTrabis(domain: string): Promise<Check> {
  if (normalizeHost(domain)?.domain !== domain) return whoisError;
  let socket: Socket | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const { connect } = await import('cloudflare:sockets');
    const connection = socket = connect({ hostname: 'whois.trabis.gov.tr', port: 43 });
    void connection.closed.catch(() => {});

    const query = async () => {
      await connection.opened;
      const writer = connection.writable.getWriter();
      try {
        await writer.write(new TextEncoder().encode(domain + '\r\n'));
      } finally {
        writer.releaseLock();
      }
      return parseTrabisWhois(domain, await boundedText(connection.readable, 16_384));
    };
    return await Promise.race([query(), new Promise<Check>(resolve => {
      timer = setTimeout(() => resolve(whoisError), 7000);
    })]);
  } catch {
    return whoisError;
  } finally {
    clearTimeout(timer);
    await socket?.close().catch(() => {});
  }
}

export async function checkDomain(domain: string, loadBootstrap = rdapBootstrap): Promise<Check> {
  const tld = domain.split('.').at(-1)!;
  if (tld === 'tr') return checkTrabis(domain);
  const bootstrap = await loadBootstrap();
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
