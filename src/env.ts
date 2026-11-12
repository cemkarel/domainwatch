export interface Env extends WorkerBindings {
  APP_ORIGIN?: string;
  WORKSPACE_OWNER_ID?: string;
  WEBHOOK_KEY?: string;
  SCANNER_URL?: string;
  SCANNER_TOKEN?: string;
}

export function workspaceOwnerId(env: Env) {
  return env.WORKSPACE_OWNER_ID?.trim() || 'shared';
}
