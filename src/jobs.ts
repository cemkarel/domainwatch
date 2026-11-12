import { day, decryptWebhook, dueThreshold } from './core.ts';
import { checkDomain, checkTls, rdapBootstrap } from './checks.ts';
import { workspaceOwnerId, type Env } from './env.ts';
import { sendSlack } from './network.ts';

interface Target {
  id: string;
  user_id: string;
  hostname: string;
  domain: string;
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

async function checks(env: Env, now: number) {
  const { results } = await env.DB.prepare(`
    SELECT t.id, t.user_id, t.hostname, t.domain, n.enabled, n.thresholds, n.version
    FROM targets t LEFT JOIN notifications n USING(user_id)
    WHERE t.user_id=? AND t.next_check<=? ORDER BY t.next_check, t.id LIMIT 2
  `).bind(workspaceOwnerId(env), now).all<Target>();
  if (!results.length) return;
  const bootstrap = await rdapBootstrap();
  for (const target of results) {
    const lease = crypto.randomUUID();
    const claim = await env.DB.prepare('UPDATE targets SET next_check=?, lease=? WHERE id=? AND next_check<=?')
      .bind(now + 10 * 60_000, lease, target.id, now).run();
    if (!claim.meta.changes) continue;

    const [domain, tls] = await Promise.all([
      checkDomain(target.domain, bootstrap), checkTls(target.hostname, env)
    ]);
    const checked = Date.now();
    const statements = [
      env.DB.prepare(`UPDATE targets SET domain_status=?, domain_expiry=?, tls_status=?, tls_expiry=?,
        checked_at=?, next_check=?, lease=NULL WHERE id=? AND lease=?`)
        .bind(domain.status, domain.expiry, tls.status, tls.expiry, checked, now + day, target.id, lease)
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
          WHERE alerts.state!='sent' AND alerts.settings_version!=excluded.settings_version
        `).bind(id, kind, check.expiry, threshold, target.version, checked, checked, target.id, checked, target.version));
      }
    }

    await env.DB.batch(statements);
    console.log({ event: 'target_checked', targetId: target.id, domain: domain.status, tls: tls.status });
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
      AND a.expiry=(CASE a.kind WHEN 'domain' THEN t.domain_expiry ELSE t.tls_expiry END)
    `).bind(alert.id, claim).first<{ encrypted_url: string }>();
    let delivery: { ok: boolean; retry: boolean; result: string; delay?: number } =
      { ok: false, retry: false, result: 'superseded' };
    if (current && Date.parse(alert.expiry) > now && env.WEBHOOK_KEY) {
      try {
        const url = await decryptWebhook(current.encrypted_url, env.WEBHOOK_KEY, alert.user_id);
        const kind = alert.kind === 'tls' ? 'TLS certificate' : 'Domain registration';
        delivery = await sendSlack(url,
          `DomainWatch · ${kind} for ${alert.hostname} expires at ${alert.expiry} (${alert.threshold}-day alert).`);
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
