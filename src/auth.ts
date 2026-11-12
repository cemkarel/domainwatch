import { createHash, timingSafeEqual } from 'node:crypto';
import type { Context, MiddlewareHandler } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { day } from './core.ts';
import type { Env } from './env.ts';

const sessionCookie = 'dw_admin_session';
const sessionAge = 7 * day;
const encoder = new TextEncoder();

interface Credentials {
  salt: string;
  password_hash: string;
  version: number;
}

interface Session {
  tokenHash: string;
  version: number;
}

export type AdminApp = { Bindings: Env; Variables: { adminSession: Session } };

function digest(value: string) {
  return createHash('sha256').update(value).digest();
}

function randomHex(bytes: number) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), byte => byte.toString(16).padStart(2, '0')).join('');
}

function credentials(env: Env) {
  return env.DB.prepare('SELECT salt, password_hash, version FROM admin_credentials WHERE id=1').first<Credentials>();
}

async function hashPassword(password: string, salt: string) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits({
    name: 'PBKDF2', hash: 'SHA-256', salt: encoder.encode(salt), iterations: 100_000
  }, key, 256);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

async function matchesPassword(password: string, stored: Credentials) {
  const hash = await hashPassword(password, stored.salt);
  return timingSafeEqual(encoder.encode(hash), encoder.encode(stored.password_hash));
}

function validPassword(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 12 && value.length <= 128;
}

function cookieOptions(c: Context<AdminApp>) {
  return { path: '/', httpOnly: true, sameSite: 'Strict' as const, secure: new URL(c.req.url).protocol === 'https:' };
}

export const requireAdmin: MiddlewareHandler<AdminApp> = async (c, next) => {
  const token = getCookie(c, sessionCookie);
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return c.json({ error: 'unauthenticated' }, 401);
  const tokenHash = digest(token).toString('hex');
  const row = await c.env.DB.prepare(`
    SELECT p.version FROM admin_sessions s JOIN admin_credentials p ON p.id=1 AND p.version=s.password_version
    WHERE s.token_hash=? AND s.expires>?
  `).bind(tokenHash, Date.now()).first<{ version: number }>();
  if (!row) return c.json({ error: 'unauthenticated' }, 401);
  c.set('adminSession', { tokenHash, version: row.version });
  await next();
};

export async function login(c: Context<AdminApp>) {
  const allowed = await c.env.LOGIN_LIMIT.limit({ key: c.req.header('CF-Connecting-IP') ?? 'local' });
  if (!allowed.success) return c.json({ error: 'rate_limited' }, 429);

  const input = await c.req.json().catch(() => null);
  if (input?.username !== 'admin' || !validPassword(input?.password)) {
    return c.json({ error: 'invalid_credentials' }, 401);
  }

  const password = input.password;
  let stored = await credentials(c.env);
  if (stored) {
    if (!await matchesPassword(password, stored)) return c.json({ error: 'invalid_credentials' }, 401);
  } else {
    const initial = c.env.ADMIN_PASSWORD;
    if (!validPassword(initial)) return c.json({ error: 'login_unconfigured' }, 503);
    if (!timingSafeEqual(digest(password), digest(initial))) return c.json({ error: 'invalid_credentials' }, 401);

    const salt = randomHex(16);
    const passwordHash = await hashPassword(password, salt);
    const created = await c.env.DB.prepare('INSERT OR IGNORE INTO admin_credentials (id,salt,password_hash) VALUES (1,?,?)')
      .bind(salt, passwordHash).run();
    stored = created.meta.changes ? { salt, password_hash: passwordHash, version: 1 } : await credentials(c.env);
    if (!stored || (!created.meta.changes && !await matchesPassword(password, stored))) {
      return c.json({ error: 'invalid_credentials' }, 401);
    }
  }

  const token = randomHex(32);
  const now = Date.now();
  const [session] = await c.env.DB.batch([
    c.env.DB.prepare(`
      INSERT INTO admin_sessions (token_hash,password_version,expires)
      SELECT ?,version,? FROM admin_credentials WHERE id=1 AND version=?
    `).bind(digest(token).toString('hex'), now + sessionAge, stored.version),
    c.env.DB.prepare(`
      DELETE FROM admin_sessions WHERE expires<=? OR password_version!=(SELECT version FROM admin_credentials WHERE id=1)
    `).bind(now)
  ]);
  if (!session.meta.changes) return c.json({ error: 'invalid_credentials' }, 401);

  setCookie(c, sessionCookie, token, { ...cookieOptions(c), maxAge: sessionAge / 1000 });
  return c.json({ ok: true });
}

export async function logout(c: Context<AdminApp>) {
  await c.env.DB.prepare('DELETE FROM admin_sessions WHERE token_hash=?').bind(c.get('adminSession').tokenHash).run();
  deleteCookie(c, sessionCookie, cookieOptions(c));
  return c.json({ ok: true });
}

export async function changePassword(c: Context<AdminApp>) {
  const input = await c.req.json().catch(() => null);
  if (!validPassword(input?.currentPassword) || !validPassword(input?.newPassword)) {
    return c.json({ error: 'invalid_password' }, 400);
  }

  const { tokenHash, version } = c.get('adminSession');
  const stored = await credentials(c.env);
  if (!stored || stored.version !== version) return c.json({ error: 'unauthenticated' }, 401);
  if (!await matchesPassword(input.currentPassword, stored)) return c.json({ error: 'incorrect_password' }, 400);
  if (input.currentPassword === input.newPassword) return c.json({ error: 'password_unchanged' }, 400);

  const salt = randomHex(16);
  const passwordHash = await hashPassword(input.newPassword, salt);
  const result = await c.env.DB.prepare(`
    UPDATE admin_credentials SET salt=?, password_hash=?, version=version+1
    WHERE id=1 AND version=? AND EXISTS (
      SELECT 1 FROM admin_sessions WHERE token_hash=? AND password_version=? AND expires>?
    )
  `).bind(salt, passwordHash, version, tokenHash, version, Date.now()).run();
  if (!result.meta.changes) return c.json({ error: 'unauthenticated' }, 401);
  deleteCookie(c, sessionCookie, cookieOptions(c));
  return c.json({ ok: true });
}
