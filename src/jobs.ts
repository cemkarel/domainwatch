import { day, decryptWebhook, dueThreshold } from './core.ts';
import { checkDomain, rdapBootstrap, type Check } from './checks.ts';
import { workspaceOwnerId, type Env } from './env.ts';
import { sendSlack } from './network.ts';
import { tlsChecks } from './tls.ts';

interface Target {
  id: string;
  hostname: string;
  domain: string;
  tls_enabled: number;
  enabled: number | null;
  thresholds: string | null;
  version: string | null;
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

const targetQuery = `
  SELECT t.id, t.hostname, t.domain, t.tls_enabled, n.enabled, n.thresholds, n.version
  FROM targets t LEFT JOIN notifications n USING(user_id)
`;

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
  env: Env, target: Target, checkTls: ReturnType<typeof tlsChecks>['check'], loadBootstrap = rdapBootstrap
) {
  const now = Date.now();
  const lease = crypto.randomUUID();
  const claim = await env.DB.prepare('UPDATE targets SET next_check=?, lease=? WHERE id=? AND next_check<=? AND tls_enabled=?')
    .bind(now + 10 * 60_000, lease, target.id, now, target.tls_enabled).run();
  if (!claim.meta.changes) return false;

  const domainCheck = settleWithin<Check>(checkDomain(target.domain, loadBootstrap),
    20_000, { status: 'rdap_error', expiry: null }).then(async result => {
    await env.DB.prepare('UPDATE targets SET domain_status=?, domain_expiry=? WHERE id=? AND lease=?')
      .bind(result.status, result.expiry, target.id, lease).run();
    return result;
  });
  const [domain, tls] = await Promise.all([
    domainCheck,
    target.tls_enabled ? settleWithin<Check>(checkTls(target.hostname), 22_000, { status: 'scanner_timeout', expiry: null })
      : { status: 'disabled', expiry: null }
  ]);
  const checked = Date.now();
  const statements = [
    env.DB.prepare(`UPDATE targets SET tls_status=?, tls_expiry=?,
      checked_at=?, next_check=?, lease=NULL WHERE id=? AND lease=?`)
      .bind(tls.status, tls.expiry, checked, checked + day, target.id, lease)
  ];

  if (target.enabled && target.thresholds && target.version) {
    const values = JSON.parse(target.thresholds) as number[];
    for (const [kind, check] of [['domain', domain], ['tls', tls]] as const) {
      if (!check.expiry) continue;
      const threshold = dueThreshold(check.expiry, values, checked);
      if (!threshold) continue;
      const id = crypto.randomUUID();
      statements.push(env.DB.prepare(`
        INSERT INTO alerts (id,target_id,kind,expiry,threshold,settings_version,next_attempt,updated_at)
        SELECT ?,t.id,?,?,?,?,?,? FROM targets t JOIN notifications n USING(user_id)
        WHERE t.id=? AND t.checked_at=? AND n.enabled=1 AND n.version=?
        ON CONFLICT(target_id,kind,expiry,threshold) DO UPDATE SET settings_version=excluded.settings_version,
          state='pending', attempts=0, next_attempt=excluded.next_attempt, updated_at=excluded.updated_at,
          last_result=NULL, claim=NULL
        WHERE alerts.state!='sent' AND (alerts.settings_version!=excluded.settings_version
          OR (alerts.kind='tls' AND alerts.last_result='superseded'))
      `).bind(id, kind, check.expiry, threshold, target.version, checked, checked, target.id, checked, target.version));
    }
  }

  const [updated] = await env.DB.batch(statements);
  if (!updated.meta.changes) return false;
  console.log({ event: 'target_checked', targetId: target.id, domain: domain.status, tls: tls.status });
  return true;
}

export async function checkNewTarget(env: Env, id: string) {
  const target = await env.DB.prepare(targetQuery + ' WHERE t.id=? AND t.user_id=?')
    .bind(id, workspaceOwnerId(env)).first<Target>();
  if (!target) return false;
  const tls = tlsChecks(env.TLS_BROWSER, [target.hostname]);
  try {
    return await checkTarget(env, target, tls.check);
  } finally {
    await settleWithin(tls.close(), 2000, undefined);
  }
}

async function checks(env: Env, now: number) {
  const { results } = await env.DB.prepare(targetQuery + `
    WHERE t.user_id=? AND t.next_check<=? ORDER BY t.next_check, t.id LIMIT 2
  `).bind(workspaceOwnerId(env), now).all<Target>();
  let bootstrap: ReturnType<typeof rdapBootstrap> | undefined;
  const loadBootstrap = () => bootstrap ??= rdapBootstrap();
  const tls = tlsChecks(env.TLS_BROWSER, results.filter(target => target.tls_enabled).map(target => target.hostname));
  try {
    for (const target of results) {
      await checkTarget(env, target, tls.check, loadBootstrap);
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
      SELECT n.encrypted_url FROM alerts a JOIN targets t ON t.id=a.target_id
      JOIN notifications n USING(user_id)
      WHERE a.id=? AND a.claim=? AND n.enabled=1 AND n.version=a.settings_version
      AND a.expiry=(CASE WHEN a.kind='domain' THEN t.domain_expiry WHEN t.tls_enabled=1 THEN t.tls_expiry END)
    `).bind(alert.id, claim).first<{ encrypted_url: string }>();
    let delivery: { ok: boolean; retry: boolean; result: string; delay?: number } =
      { ok: false, retry: false, result: 'superseded' };
    if (current && Date.parse(alert.expiry) > now && env.WEBHOOK_KEY) {
      try {
        const url = await decryptWebhook(current.encrypted_url, env.WEBHOOK_KEY, alert.user_id);
        const kind = alert.kind === 'tls' ? 'TLS certificate' : 'Domain registration';
        const expires = alert.kind === 'domain' && alert.hostname.endsWith('.tr')
          ? `expires on ${alert.expiry.slice(0, 10)}` : `expires at ${alert.expiry}`;
        delivery = await sendSlack(url,
          `DomainWatch · ${kind} for ${alert.hostname} ${expires} (${alert.threshold}-day alert).`);
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
  const now = Date.now();
  const results = await Promise.allSettled([checks(env, now), deliveries(env, now)]);
  if (results.some(result => result.status === 'rejected')) throw new Error('Scheduled job failed');
}
