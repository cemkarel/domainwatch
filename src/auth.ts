import { Hono } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { hash, token } from './core.ts';
import type { Env } from './env.ts';
import { boundedJson } from './network.ts';

export interface User { id: string; login: string }
export type App = { Bindings: Env; Variables: { user: User } };
export const sessionCookie = 'dw_session';
const sessionAge = 7 * 24 * 60 * 60;
const oauth = new Hono<App>();

export function cookieOptions(origin: string, maxAge: number) {
  return { path: '/', httpOnly: true, sameSite: 'Lax' as const, secure: origin.startsWith('https:'), maxAge };
}

oauth.use('*', async (c, next) => {
  const { APP_ORIGIN, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET } = c.env;
  if (!APP_ORIGIN || !GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) return c.text('GitHub sign-in is unconfigured.', 503);
  if (new URL(c.req.url).origin !== APP_ORIGIN) return c.text('Unexpected application origin.', 400);
  const allowed = await c.env.LOGIN_LIMIT.limit({ key: c.req.header('CF-Connecting-IP') ?? 'local' });
  if (!allowed.success) return c.text('Try again in a minute.', 429);
  await next();
});

oauth.get('/github', async c => {
  const origin = c.env.APP_ORIGIN!;
  const state = token();
  const verifier = token();
  setCookie(c, 'dw_oauth', state + '.' + verifier, cookieOptions(origin, 600));
  const url = new URL('https://github.com/login/oauth/authorize');
  url.search = new URLSearchParams({
    client_id: c.env.GITHUB_CLIENT_ID!,
    redirect_uri: origin + '/auth/github/callback',
    state,
    code_challenge: (await hash(verifier)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'),
    code_challenge_method: 'S256'
  }).toString();
  return c.redirect(url.toString());
});

oauth.get('/github/callback', async c => {
  const origin = c.env.APP_ORIGIN!;
  const [state, verifier] = getCookie(c, 'dw_oauth')?.split('.') ?? [];
  setCookie(c, 'dw_oauth', '', cookieOptions(origin, 0));
  const code = c.req.query('code');
  if (!state || !verifier || !code || state !== c.req.query('state')) {
    return c.redirect('/?auth=failed');
  }
  try {
    const response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(8000),
      headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: c.env.GITHUB_CLIENT_ID!, client_secret: c.env.GITHUB_CLIENT_SECRET!,
        redirect_uri: origin + '/auth/github/callback', code, code_verifier: verifier
      })
    });
    const data = await boundedJson(response, 8192) as { access_token?: string };
    if (!response.ok || !data.access_token) return c.redirect('/?auth=failed');
    const profile = await fetch('https://api.github.com/user', {
      redirect: 'manual', signal: AbortSignal.timeout(8000),
      headers: { Accept: 'application/vnd.github+json', Authorization: 'Bearer ' + data.access_token,
        'User-Agent': 'DomainWatch' }
    });
    const user = await boundedJson(profile, 32_768) as { id: number; login: string };
    if (!profile.ok || !Number.isSafeInteger(user.id) || typeof user.login !== 'string') {
      return c.redirect('/?auth=failed');
    }

    const session = token();
    const id = String(user.id);
    const previous = getCookie(c, sessionCookie);
    const queries = [
      c.env.DB.prepare('INSERT INTO users VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET login=excluded.login')
        .bind(id, user.login),
      c.env.DB.prepare('INSERT INTO sessions VALUES (?, ?, ?)').bind(await hash(session), id, Date.now() + sessionAge * 1000)
    ];
    if (previous) queries.push(c.env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await hash(previous)));
    await c.env.DB.batch(queries);
    setCookie(c, sessionCookie, session, cookieOptions(origin, sessionAge));
    return c.redirect('/');
  } catch {
    console.warn('github_sign_in_failed');
    return c.redirect('/?auth=failed');
  }
});

export default oauth;
