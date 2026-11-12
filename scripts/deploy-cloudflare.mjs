import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const wrangler = fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url));
const root = fileURLToPath(new URL('../', import.meta.url));
const databaseName = 'domainwatch';

function run(args, capture = false) {
  const result = spawnSync(process.execPath, [wrangler, ...args], {
    cwd: root,
    encoding: 'utf8',
    stdio: capture ? ['ignore', 'pipe', 'inherit'] : 'inherit'
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`wrangler ${args.join(' ')} failed (${result.signal ?? result.status}).`);
  }
  return result.stdout;
}

function databaseExists() {
  const databases = JSON.parse(run(['d1', 'list', '--json'], true));
  return databases.some(database => database.name === databaseName);
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
  run(['deploy']);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
