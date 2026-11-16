import { day, decryptWebhook, thresholds } from './core.ts';
import { checkDomain, rdapBootstrap, type Check } from './checks.ts';
import { workspaceOwnerId, type Env } from './env.ts';
import { sendSlack } from './network.ts';
import { tlsChecks } from './tls.ts';

interface Target {
  id: string;
  hostname: string;
  domain: string;
  tls_enabled: number;
  next_check: number;
  tls_next_check: number;
}

interface Alert {
  id: string;
  kind: 'domain' | 'tls';
  expiry: string;
  threshold: number;
  attempts: number;
  hostname: string;
  user_id: string;
}

const targetQuery = 'SELECT id, hostname, domain, tls_enabled, next_check, tls_next_check FROM targets';
const warningWindow = Math.max(...thresholds) * day;
const retryInterval = 60 * 60_000;

const scheduledCheckLimit = 10;
// Leave time for the last lookup and browser cleanup before the next minute.
const scheduledCheckStartWindow = 35_000;

async function settleWithin<T>(operation: Promise<T>, ms: number, fallback: T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([operation, new Promise<T>(resolve => {
      timer = setTimeout(() => resolve(fallback), ms);
    })]);
  } finally {
    clearTimeout(timer);
  }
}

async function checkTarget(
  env: Env, target: Target, checkTls: ReturnType<typeof tlsChecks>['check'],
  loadBootstrap = rdapBootstrap, dueAt = Date.now()
) {
  const now = Date.now();
  const domainDue = target.next_check <= dueAt;
  const tlsDue = target.tls_enabled === 1 && target.tls_next_check <= dueAt;
  if (!domainDue && !tlsDue) return false;
  const lease = crypto.randomUUID();
  const claim = await env.DB.prepare(`
    UPDATE targets SET lease_until=?, lease=?
    WHERE id=? AND lease_until<=? AND next_check=? AND tls_next_check=? AND tls_enabled=?
  `).bind(now + 10 * 60_000, lease, target.id, now, target.next_check, target.tls_next_check, target.tls_enabled).run();
  if (!claim.meta.changes) return false;

  const [domain, tls] = await Promise.all([
    domainDue ? settleWithin<Check>(checkDomain(target.domain, loadBootstrap),
      20_000, { status: 'rdap_error', expiry: null }) : undefined,
    tlsDue ? settleWithin<Check>(checkTls(target.hostname), 22_000, { status: 'scanner_timeout', expiry: null })
      : undefined
  ]);
  const checked = Date.now();
  const updates = ['lease=NULL', 'lease_until=0'];
  const args: (number | string | null)[] = [];
  if (domain) {
    const temporary = ['rdap_error', 'whois_error', 'bootstrap_unavailable'].includes(domain.status);
    const windowStarts = domain.expiry ? Date.parse(domain.expiry) - warningWindow : checked;
    const nextCheck = temporary ? checked + retryInterval
      : windowStarts <= checked ? checked + day : Math.min(checked + 7 * day, windowStarts);
    updates.push('domain_status=?', temporary ? 'domain_expiry=COALESCE(?,domain_expiry)' : 'domain_expiry=?',
      'checked_at=?', 'next_check=?');
    args.push(domain.status, domain.expiry, checked, nextCheck);
  }
  if (tls) {
    updates.push('tls_status=?', 'tls_expiry=?', 'tls_checked_at=?', 'tls_next_check=?');
    args.push(tls.status, tls.expiry, checked, checked + day);
  }

  const updated = await env.DB.prepare(`UPDATE targets SET ${updates.join(', ')} WHERE id=? AND lease=?`)
    .bind(...args, target.id, lease).run();
  if (!updated.meta.changes) return false;
  console.log({ event: 'target_checked', targetId: target.id, domain: domain?.status, tls: tls?.status });
  return true;
}

async function queueAlerts(env: Env, now: number, targetId?: string) {
  const owner = workspaceOwnerId(env);
  const enabled = await env.DB.prepare('SELECT 1 FROM notifications WHERE user_id=? AND enabled=1').bind(owner).first();
  if (!enabled) return;
  const from = new Date(now).toISOString();
  const until = new Date(now + warningWindow).toISOString();
  await env.DB.batch((['domain', 'tls'] as const).map(kind => {
    const expiry = `t.${kind}_expiry`;
    return env.DB.prepare(`
      INSERT INTO alerts (id,target_id,kind,expiry,threshold,settings_version,next_attempt,updated_at)
      SELECT lower(hex(randomblob(16))),id,?,expiry,threshold,version,?,?
      FROM (
        SELECT t.id, ${expiry} AS expiry, n.version,
          (SELECT min(value) FROM json_each(n.thresholds)
            WHERE round(unixepoch(${expiry},'subsec') * 1000) <= ? + value * ?) AS threshold
        FROM targets t JOIN notifications n USING(user_id)
        WHERE t.user_id=? AND n.enabled=1 AND ${expiry}>? AND ${expiry}<=?
          ${kind === 'tls' ? 'AND t.tls_enabled=1' : ''}
          ${targetId ? 'AND t.id=?' : ''}
      ) WHERE threshold IS NOT NULL
      ON CONFLICT(target_id,kind,expiry,threshold) DO UPDATE SET settings_version=excluded.settings_version,
        state='pending', attempts=0, next_attempt=excluded.next_attempt, updated_at=excluded.updated_at,
        last_result=NULL, claim=NULL
      WHERE alerts.state!='sent' AND (alerts.settings_version!=excluded.settings_version
        OR (alerts.kind='tls' AND alerts.last_result='superseded'))
    `).bind(kind, now, now, now, day, owner, from, until, ...(targetId ? [targetId] : []));
  }));
}

export async function checkTargetNow(env: Env, id: string) {
  const target = await env.DB.prepare(targetQuery + ' WHERE id=? AND user_id=?')
    .bind(id, workspaceOwnerId(env)).first<Target>();
  if (!target) return false;
  const tls = tlsChecks(env.TLS_BROWSER, [target.hostname]);
  try {
    if (await checkTarget(env, target, tls.check)) await queueAlerts(env, Date.now(), id);
  } finally {
    await settleWithin(tls.close(), 2000, undefined);
  }
}

async function checks(env: Env, now: number) {
  const { results } = await env.DB.prepare(targetQuery + `
    WHERE user_id=? AND lease_until<=? AND (next_check<=? OR (tls_enabled=1 AND tls_next_check<=?))
    ORDER BY CASE WHEN tls_enabled=1 THEN min(next_check,tls_next_check) ELSE next_check END, id LIMIT ?
  `).bind(workspaceOwnerId(env), now, now, now, scheduledCheckLimit).all<Target>();
  let bootstrap: ReturnType<typeof rdapBootstrap> | undefined;
  const loadBootstrap = () => bootstrap ??= rdapBootstrap();
  const tls = tlsChecks(env.TLS_BROWSER, results
    .filter(target => target.tls_enabled && target.tls_next_check <= now).map(target => target.hostname));
  try {
    for (const target of results) {
      if (Date.now() - now >= scheduledCheckStartWindow) break;
      await checkTarget(env, target, tls.check, loadBootstrap, now);
    }
  } finally {
    await settleWithin(tls.close(), 2000, undefined);
  }
}

async function deliveries(env: Env, now: number) {
  const { results } = await env.DB.prepare(`
    SELECT a.id, a.kind, a.expiry, a.threshold, a.attempts, t.hostname, t.user_id
    FROM alerts a JOIN targets t ON t.id=a.target_id
    WHERE t.user_id=? AND a.state='pending' AND a.next_attempt<=? ORDER BY a.next_attempt LIMIT 4
  `).bind(workspaceOwnerId(env), now).all<Alert>();
  for (const alert of results) {
    const claim = crypto.randomUUID();
    const result = await env.DB.prepare(`
      UPDATE alerts SET next_attempt=?, claim=? WHERE id=? AND state='pending' AND next_attempt<=?
    `).bind(now + 120_000, claim, alert.id, now).run();
    if (!result.meta.changes) continue;
    const current = await env.DB.prepare(`
      SELECT n.encrypted_url, t.domain_status FROM alerts a JOIN targets t ON t.id=a.target_id
      JOIN notifications n USING(user_id)
      WHERE a.id=? AND a.claim=? AND n.enabled=1 AND n.version=a.settings_version
      AND a.expiry=(CASE WHEN a.kind='domain' THEN t.domain_expiry WHEN t.tls_enabled=1 THEN t.tls_expiry END)
    `).bind(alert.id, claim).first<{ encrypted_url: string; domain_status: string }>();
    let delivery: { ok: boolean; retry: boolean; result: string; delay?: number } =
      { ok: false, retry: false, result: 'superseded' };
    if (current && Date.parse(alert.expiry) > now && env.WEBHOOK_KEY) {
      try {
        const url = await decryptWebhook(current.encrypted_url, env.WEBHOOK_KEY, alert.user_id);
        const kind = alert.kind === 'tls' ? 'TLS certificate' : 'Domain registration';
        const expires = alert.kind === 'domain' && alert.hostname.endsWith('.tr')
          ? `expires on ${alert.expiry.slice(0, 10)}` : `expires at ${alert.expiry}`;
        const stale = alert.kind === 'domain' && current.domain_status !== 'ok'
          ? ' Based on the last verified expiry date.' : '';
        delivery = await sendSlack(url,
          `DomainWatch · ${kind} for ${alert.hostname} ${expires} (${alert.threshold}-day alert).${stale}`);
      } catch {
        delivery = { ok: false, retry: false, result: 'webhook_decryption_error' };
      }
    }
    const attempts = alert.attempts + 1;
    const state = delivery.ok ? 'sent' : delivery.retry && attempts < 5 ? 'pending' : 'failed';
    const next = Date.now() + Math.max(5 * 60_000 * 2 ** (attempts - 1), delivery.delay ?? 0);
    await env.DB.prepare(`UPDATE alerts SET state=?, attempts=?, next_attempt=?, last_result=?,
      updated_at=?, claim=NULL WHERE id=? AND claim=?`)
      .bind(state, attempts, next, delivery.result, Date.now(), alert.id, claim).run();
    console.log({ event: 'alert_delivery', alertId: alert.id, attempts, state, result: delivery.result });
  }
}

export async function scheduled(env: Env) {
  try {
    await checks(env, Date.now());
    await queueAlerts(env, Date.now());
  } finally {
    await deliveries(env, Date.now());
  }
}
