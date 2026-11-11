export interface Env extends WorkerBindings {
  APP_ORIGIN?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  WEBHOOK_KEY?: string;
  SCANNER_URL?: string;
  SCANNER_TOKEN?: string;
}
