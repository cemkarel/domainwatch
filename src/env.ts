interface RuntimeVariables {
  APP_ORIGIN?: string;
  ADMIN_PASSWORD?: string;
  WORKSPACE_OWNER_ID?: string;
  WEBHOOK_KEY?: string;
  SCANNER_URL?: string;
  SCANNER_TOKEN?: string;
}

export type Env = Omit<WorkerBindings, keyof RuntimeVariables> & RuntimeVariables;

export function workspaceOwnerId(env: Env) {
  return env.WORKSPACE_OWNER_ID?.trim() || 'shared';
}
