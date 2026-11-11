import { getDomain } from 'tldts';

export const thresholds = [30, 14, 7, 3, 1] as const;
export const day = 86_400_000;

export function normalizeHost(input: unknown) {
  if (typeof input !== 'string' || input.length > 253) return null;
  const raw = input.trim().replace(/\.$/, '');
  if (!raw || /[\s/:?#@%\\\[\]]/u.test(raw)) return null;
  try {
    const hostname = new URL('https://' + raw).hostname;
    if (hostname.length > 253 || !hostname.split('.').every(
      label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
    )) return null;
    const domain = getDomain(hostname, { allowPrivateDomains: false });
    const tld = hostname.split('.').at(-1);
    if (!domain || !tld || /^(?:\d+|localhost|local|internal|test|invalid|example|onion|arpa)$/.test(tld)) return null;
    return { hostname, domain };
  } catch {
    return null;
  }
}

export function webhookUrl(input: unknown) {
  if (typeof input !== 'string') return null;
  const value = input.trim();
  return /^https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9_-]{10,200}$/.test(value)
    ? value : null;
}

export function parseThresholds(input: unknown): number[] | null {
  if (!Array.isArray(input) || input.length < 1 || input.length > thresholds.length) return null;
  if (!input.every(value => thresholds.some(threshold => value === threshold))) return null;
  if (new Set(input).size !== input.length) return null;
  return [...input].sort((a, b) => a - b);
}

export function dueThreshold(expiry: string, values: number[], now: number) {
  const remaining = Date.parse(expiry) - now;
  if (!Number.isFinite(remaining) || remaining <= 0) return undefined;
  return values.filter(value => remaining <= value * day).sort((a, b) => a - b)[0];
}

const encoder = new TextEncoder();
const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const bytes = (value: string) => Uint8Array.from(atob(value), char => char.charCodeAt(0));

export function token() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function hash(value: string) {
  return base64(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))));
}

async function webhookKey(secret: string) {
  const decoded = bytes(secret);
  if (decoded.length !== 32) throw new Error('Invalid webhook key');
  return crypto.subtle.importKey('raw', decoded, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function encryptWebhook(value: string, secret: string, tenant: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(tenant) },
    await webhookKey(secret), encoder.encode(value)
  );
  return base64(iv) + '.' + base64(new Uint8Array(encrypted));
}

export async function decryptWebhook(value: string, secret: string, tenant: string) {
  const [iv, encrypted] = value.split('.');
  const result = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes(iv), additionalData: encoder.encode(tenant) },
    await webhookKey(secret), bytes(encrypted)
  );
  return new TextDecoder().decode(result);
}
