import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { changePassword, login, logout, requireAdmin, type AdminApp } from './auth.ts';
import { decryptWebhook, encryptWebhook, normalizeHost, parseThresholds, thresholds, webhookUrl } from './core.ts';
import { workspaceOwnerId, type Env } from './env.ts';
import { checkNewTarget, scheduled } from './jobs.ts';
import { sendSlack } from './network.ts';

const app = new Hono<AdminApp>();
const api = new Hono<AdminApp>();
app.use('*', async (c, next) => {
  await next();
  c.header('Cache-Control', 'no-store');
  c.header('Referrer-Policy', 'no-referrer');
  c.header('X-Content-Type-Options', 'nosniff');
});
api.use('*', async (c, next) => {
  if (!['GET', 'HEAD'].includes(c.req.method)) {
    const origin = c.env.APP_ORIGIN || new URL(c.req.url).origin;
    if (c.req.header('Origin') !== origin) {
      return c.json({ error: 'invalid_origin' }, 403);
    }
    const limit = await c.env.WRITE_LIMIT.limit({ key: workspaceOwnerId(c.env) });
    if (!limit.success) return c.json({ error: 'rate_limited' }, 429);
  }
  await next();
});
api.use('*', bodyLimit({ maxSize: 4096, onError: c => c.json({ error: 'body_too_large' }, 413) }));
api.post('/auth/login', login);
api.use('*', requireAdmin);
api.get('/auth/session', c => c.json({ ok: true }));
api.post('/auth/logout', logout);
api.put('/auth/password', changePassword);

api.get('/targets', async c => {
  const { results } = await c.env.DB.prepare(`
    SELECT id, hostname, domain, domain_status, domain_expiry, tls_status, tls_expiry, checked_at
    FROM targets WHERE user_id=? ORDER BY hostname
  `).bind(workspaceOwnerId(c.env)).all();
  return c.json(results);
});

api.post('/targets', async c => {
  const body = await c.req.json().catch(() => null);
  const host = normalizeHost(body?.hostname);
  if (!host) return c.json({ error: 'invalid_hostname' }, 400);
  const user = workspaceOwnerId(c.env);
  const id = crypto.randomUUID();
  const result = await c.env.DB.prepare(`
    INSERT INTO targets(id,user_id,hostname,domain)
    SELECT ?,?,?,? WHERE (SELECT COUNT(*) FROM targets WHERE user_id=?)<25
      AND (SELECT COUNT(*) FROM targets)<400
    ON CONFLICT(user_id,hostname) DO NOTHING
  `).bind(id, user, host.hostname, host.domain, user).run();
  if (!result.meta.changes) {
    const duplicate = await c.env.DB.prepare('SELECT id FROM targets WHERE user_id=? AND hostname=?')
      .bind(user, host.hostname).first();
    return c.json({ error: duplicate ? 'duplicate_hostname' : 'target_limit' }, 409);
  }
  const checked = await checkNewTarget(c.env, id).catch(() => {
    console.error({ event: 'first_check_failed', targetId: id });
    return false;
  });
  return c.json({ id, checked }, 201);
});

api.delete('/targets/:id', async c => {
  const result = await c.env.DB.prepare('DELETE FROM targets WHERE id=? AND user_id=?')
    .bind(c.req.param('id'), workspaceOwnerId(c.env)).run();
  return result.meta.changes ? c.json({ ok: true }) : c.json({ error: 'not_found' }, 404);
});

interface Notification {
  encrypted_url: string;
  enabled: number;
  thresholds: string;
  version: string;
}

function settings(env: Env, id: string) {
  return env.DB.prepare('SELECT encrypted_url, enabled, thresholds, version FROM notifications WHERE user_id=?')
    .bind(id).first<Notification>();
}

api.get('/settings/slack', async c => {
  const user = workspaceOwnerId(c.env);
  const row = await settings(c.env, user);
  let url: string | null = null;
  let webhookError: string | null = null;
  if (row) {
    if (!c.env.WEBHOOK_KEY) webhookError = 'encryption_unconfigured';
    else {
      try {
        url = await decryptWebhook(row.encrypted_url, c.env.WEBHOOK_KEY, user);
      } catch {
        webhookError = 'webhook_decryption_error';
      }
    }
  }
  return c.json({ configured: Boolean(row), enabled: Boolean(row?.enabled),
    thresholds: row ? JSON.parse(row.thresholds) : thresholds, url, webhookError });
});

api.put('/settings/slack', async c => {
  const input = await c.req.json().catch(() => null);
  const values = parseThresholds(input?.thresholds);
  if (typeof input?.enabled !== 'boolean' || !values) return c.json({ error: 'invalid_settings' }, 400);
  const user = workspaceOwnerId(c.env);
  const previous = await settings(c.env, user);
  let encrypted = previous?.encrypted_url;
  if (input.url !== undefined && input.url !== '') {
    const url = webhookUrl(input.url);
    if (!url) return c.json({ error: 'invalid_webhook' }, 400);
    if (!c.env.WEBHOOK_KEY) return c.json({ error: 'encryption_unconfigured' }, 503);
    encrypted = await encryptWebhook(url, c.env.WEBHOOK_KEY, user);
  }
  if (!encrypted) return c.json({ error: 'webhook_required' }, 400);
  const serialized = JSON.stringify(values);
  if (previous?.encrypted_url === encrypted && previous.enabled === Number(input.enabled)
    && previous.thresholds === serialized) return c.json({ ok: true });
  const version = crypto.randomUUID();
  const update = previous
    ? c.env.DB.prepare(`UPDATE notifications SET encrypted_url=?, enabled=?, thresholds=?, version=?
      WHERE user_id=? AND version=?`).bind(encrypted, Number(input.enabled), serialized, version, user, previous.version)
    : c.env.DB.prepare('INSERT OR IGNORE INTO notifications VALUES (?, ?, ?, ?, ?)')
      .bind(user, encrypted, Number(input.enabled), serialized, version);
  const result = await update.run();
  return result.meta.changes ? c.json({ ok: true }) : c.json({ error: 'settings_changed' }, 409);
});

api.post('/settings/slack/test', async c => {
  const user = workspaceOwnerId(c.env);
  const allowed = await c.env.TEST_LIMIT.limit({ key: user });
  if (!allowed.success) return c.json({ error: 'rate_limited' }, 429);
  const input = c.req.raw.body ? await c.req.json().catch(() => null) : {};
  if (!input || typeof input !== 'object' || Array.isArray(input)) return c.json({ error: 'invalid_webhook' }, 400);
  let url: string | null;
  if (input.url !== undefined && input.url !== '') {
    url = webhookUrl(input.url);
    if (!url) return c.json({ error: 'invalid_webhook' }, 400);
  } else {
    const row = await settings(c.env, user);
    if (!row) return c.json({ error: 'webhook_required' }, 400);
    if (!c.env.WEBHOOK_KEY) return c.json({ error: 'encryption_unconfigured' }, 503);
    try {
      url = await decryptWebhook(row.encrypted_url, c.env.WEBHOOK_KEY, user);
    } catch {
      return c.json({ error: 'webhook_decryption_error' }, 503);
    }
  }
  const result = await sendSlack(url, 'DomainWatch · Test message. Your Slack webhook is working.');
  console.log({ event: 'slack_test', result: result.result });
  return result.ok ? c.json({ ok: true }) : c.json({ error: result.result }, 502);
});

api.get('/alerts', async c => {
  const { results } = await c.env.DB.prepare(`
    SELECT a.id, t.hostname, a.kind, a.expiry, a.threshold, a.state, a.attempts, a.last_result, a.updated_at
    FROM alerts a JOIN targets t ON t.id=a.target_id
    WHERE t.user_id=? ORDER BY a.updated_at DESC LIMIT 25
  `).bind(workspaceOwnerId(c.env)).all();
  return c.json(results);
});

app.route('/api', api);
app.notFound(c => c.json({ error: 'not_found' }, 404));
app.onError((_error, c) => {
  console.error({ event: 'request_failed', method: c.req.method });
  return c.json({ error: 'internal_error' }, 500);
});

export default {
  fetch: app.fetch,
  scheduled: (_controller, env) => scheduled(env)
} satisfies ExportedHandler<Env>;
