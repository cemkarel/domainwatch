import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const wrangler = fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url));
const root = fileURLToPath(new URL('../', import.meta.url));
const databaseName = 'domainwatch';

function run(args, { capture = false, allowMissingWorker = false } = {}) {
  const result = spawnSync(process.execPath, [wrangler, ...args], {
    cwd: root,
    encoding: 'utf8',
    stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit'
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    if (allowMissingWorker && /Worker "[^"]+" not found\./.test(result.stderr ?? '')) return null;
    if (result.stderr) process.stderr.write(result.stderr);
    throw new Error(`wrangler ${args.join(' ')} failed (${result.signal ?? result.status}).`);
  }
  return result.stdout;
}

function databaseExists() {
  const databases = JSON.parse(run(['d1', 'list', '--json'], { capture: true }));
  return databases.some(database => database.name === databaseName);
}

function hasWebhookKey() {
  const result = run(['secret', 'list', '--format', 'json'], { capture: true, allowMissingWorker: true });
  return result !== null && JSON.parse(result).some(secret => secret.name === 'WEBHOOK_KEY');
}

function query(sql) {
  return JSON.parse(run(['d1', 'execute', 'DB', '--remote', '--json', '--command', sql], { capture: true }))[0].results;
}

function deployWithWebhookKey() {
  if (query('SELECT EXISTS(SELECT 1 FROM notifications) AS has_webhooks')[0].has_webhooks) {
    console.warn('Existing Slack settings need their original WEBHOOK_KEY. Deploy will preserve any configured value.');
    run(['deploy']);
    return;
  }

  const directory = mkdtempSync(join(tmpdir(), 'domainwatch-deploy-'));
  try {
    const secrets = join(directory, 'secrets.json');
    writeFileSync(secrets, JSON.stringify({ WEBHOOK_KEY: randomBytes(32).toString('base64') }), { mode: 0o600 });
    run(['deploy', '--secrets-file', secrets]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function deploy() {
  if (hasWebhookKey()) return run(['deploy']);

  // Avoid replacing the first key if two production builds start together.
  const holder = randomBytes(16).toString('hex');
  const lock = query(`
    INSERT INTO webhook_key_deploy_lock (id, holder, expires_at) VALUES (1, '${holder}', unixepoch()+1800)
    ON CONFLICT (id) DO UPDATE SET holder=excluded.holder, expires_at=excluded.expires_at
      WHERE webhook_key_deploy_lock.expires_at<=unixepoch()
    RETURNING holder
  `);
  if (!lock.length) {
    if (hasWebhookKey()) return run(['deploy']);
    throw new Error('Another deployment is initializing WEBHOOK_KEY. Retry after that deployment finishes.');
  }
  try {
    return hasWebhookKey() ? run(['deploy']) : deployWithWebhookKey();
  } finally {
    query(`DELETE FROM webhook_key_deploy_lock WHERE holder='${holder}'`);
  }
}

function ensureDatabase() {
  if (databaseExists()) return;

  try {
    run(['d1', 'create', databaseName, '--no-update-config']);
  } catch (error) {
    // Another build may have created the database after the first lookup.
    if (!databaseExists()) throw error;
  }
}

try {
  ensureDatabase();
  run(['d1', 'migrations', 'apply', 'DB', '--remote']);
} catch (error) {
  console.error(error.message);
  console.error('The Workers Builds token needs D1 Edit in the same Cloudflare account as the Worker.');
  process.exit(1);
}

try {
  deploy();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
