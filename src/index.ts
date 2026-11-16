import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { changePassword, login, logout, requireAdmin, type AdminApp } from './auth.ts';
import { decryptWebhook, encryptWebhook, normalizeHost, parseThresholds, thresholds, webhookUrl } from './core.ts';
import { workspaceOwnerId, type Env } from './env.ts';
import { checkTargetNow, scheduled } from './jobs.ts';
import { sendSlack } from './network.ts';

const app = new Hono<AdminApp>();
const api = new Hono<AdminApp>();
const targetColumns = `id, hostname, domain, domain_status, domain_expiry, tls_enabled, tls_status, tls_expiry,
  checked_at, tls_checked_at, (next_check=0 OR (tls_enabled=1 AND tls_next_check=0) OR lease_until>?) AS check_pending`;
const targetPageSize = 25;
const limitBody = bodyLimit({ maxSize: 4096, onError: c => c.json({ error: 'body_too_large' }, 413) });
const limitBulkBody = bodyLimit({ maxSize: 64 * 1024, onError: c => c.json({ error: 'bulk_body_too_large' }, 413) });
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
api.use('*', (c, next) => (c.req.method === 'POST' && c.req.path === '/api/targets/bulk' ? limitBulkBody : limitBody)(c, next));
api.post('/auth/login', login);
api.use('*', requireAdmin);
api.get('/auth/session', c => c.json({ ok: true }));
api.post('/auth/logout', logout);
api.put('/auth/password', changePassword);

api.get('/targets', async c => {
  const { results } = await c.env.DB.prepare(`
    SELECT ${targetColumns}
    FROM targets WHERE user_id=? ORDER BY hostname
  `).bind(Date.now(), workspaceOwnerId(c.env)).all();
  return c.json(results);
});

api.get('/targets/page', async c => {
  const page = c.req.query('page') ?? '1';
  const offset = (Number(page) - 1) * targetPageSize;
  if (!/^[1-9][0-9]*$/.test(page) || !Number.isSafeInteger(offset)) {
    return c.json({ error: 'invalid_page' }, 400);
  }
  const search = c.req.query('q')?.trim().toLowerCase() ?? '';
  const sort = c.req.query('sort');
  const order = sort === 'domain_expiry' || sort === 'tls_expiry' ? `${sort} ASC NULLS LAST, hostname` : 'hostname';
  const matches = '(instr(hostname, ?) > 0 OR instr(domain, ?) > 0)';
  const user = workspaceOwnerId(c.env);
  const searchParams = search ? [search, search] : [];
  const [rows, counts] = await c.env.DB.batch([
    c.env.DB.prepare(`
      SELECT ${targetColumns} FROM targets WHERE user_id=?${search ? ` AND ${matches}` : ''}
      ORDER BY ${order} LIMIT ? OFFSET ?
    `).bind(Date.now(), user, ...searchParams, targetPageSize, offset),
    c.env.DB.prepare(`
      SELECT COUNT(*) AS total, COUNT(*) ${search ? `FILTER (WHERE ${matches})` : ''} AS matched
      FROM targets WHERE user_id=?
    `).bind(...searchParams, user)
  ]);
  const { total, matched } = counts.results[0] as { total: number; matched: number };
  return c.json({ targets: rows.results, hasNext: offset + rows.results.length < matched,
    total, matched, totalPages: Math.max(1, Math.ceil(matched / targetPageSize)) });
});

function startTargetCheck(ctx: Pick<ExecutionContext, 'waitUntil'>, env: Env, id: string) {
  ctx.waitUntil(checkTargetNow(env, id).catch(() => {
    console.error({ event: 'target_check_failed', targetId: id });
  }));
}

api.post('/targets', async c => {
  const body = await c.req.json().catch(() => null);
  const host = normalizeHost(body?.hostname);
  if (!host) return c.json({ error: 'invalid_hostname' }, 400);
  const user = workspaceOwnerId(c.env);
  const id = crypto.randomUUID();
  const result = await c.env.DB.prepare(`
    INSERT INTO targets(id,user_id,hostname,domain,tls_status)
    VALUES (?,?,?,?,'disabled')
    ON CONFLICT(user_id,hostname) DO NOTHING
  `).bind(id, user, host.hostname, host.domain).run();
  if (!result.meta.changes) return c.json({ error: 'duplicate_hostname' }, 409);
  startTargetCheck(c.executionCtx, c.env, id);
  return c.json({ id, checked: false }, 201);
});

api.post('/targets/bulk', async c => {
  const body = await c.req.json().catch(() => null);
  if (typeof body?.hostnames !== 'string') return c.json({ error: 'bulk_input_required' }, 400);
  const entries = body.hostnames.split(/[\s,;]+/u).filter(Boolean);
  if (!entries.length) return c.json({ error: 'bulk_input_required' }, 400);

  const hosts = new Map<string, string>();
  const invalid = new Set<string>();
  let validCount = 0;
  for (const entry of entries) {
    const host = normalizeHost(entry);
    if (!host) {
      invalid.add(entry);
      continue;
    }
    validCount++;
    hosts.set(host.hostname, host.domain);
  }

  let added = 0;
  if (hosts.size) {
    const rows = Array.from(hosts, ([hostname, domain]) => ({ id: crypto.randomUUID(), hostname, domain }));
    // SQLite needs a WHERE clause before ON CONFLICT in INSERT ... SELECT.
    const result = await c.env.DB.prepare(`
      INSERT INTO targets (id, user_id, hostname, domain, tls_status)
      SELECT value->>'id', ?, value->>'hostname', value->>'domain', 'disabled'
      FROM json_each(?) WHERE true
      ON CONFLICT(user_id, hostname) DO NOTHING
    `).bind(workspaceOwnerId(c.env), JSON.stringify(rows)).run();
    added = result.meta.changes;
  }
  return c.json({ added, duplicates: validCount - added, invalid: [...invalid] });
});

api.put('/targets/:id/tls', async c => {
  const body = await c.req.json().catch(() => null);
  if (typeof body?.enabled !== 'boolean') return c.json({ error: 'invalid_tls_setting' }, 400);
  const enabled = Number(body.enabled);
  const id = c.req.param('id');
  const user = workspaceOwnerId(c.env);
  const result = await c.env.DB.prepare(`
    UPDATE targets SET tls_enabled=?, tls_status=?, tls_expiry=NULL,
      tls_next_check=0, tls_checked_at=NULL, lease=NULL, lease_until=0
    WHERE id=? AND user_id=? AND tls_enabled!=?
  `).bind(enabled, enabled ? 'pending' : 'disabled', id, user, enabled).run();
  if (!result.meta.changes) {
    const target = await c.env.DB.prepare('SELECT id FROM targets WHERE id=? AND user_id=?').bind(id, user).first();
    if (!target) return c.json({ error: 'not_found' }, 404);
  } else if (enabled) {
    startTargetCheck(c.executionCtx, c.env, id);
  }
  return c.json({ ok: true });
});

api.post('/targets/:id/check', async c => {
  const id = c.req.param('id');
  const result = await c.env.DB.prepare(`
    UPDATE targets SET next_check=0, tls_next_check=0 WHERE id=? AND user_id=?
  `).bind(id, workspaceOwnerId(c.env)).run();
  if (!result.meta.changes) return c.json({ error: 'not_found' }, 404);
  startTargetCheck(c.executionCtx, c.env, id);
  return c.json({ ok: true }, 202);
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
