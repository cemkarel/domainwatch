import { webhookUrl } from './core.ts';

export async function boundedText(stream: ReadableStream<Uint8Array>, limit: number): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let size = 0;
  let body = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return body + decoder.decode();
      size += value.byteLength;
      if (size > limit) throw new Error('Response too large');
      body += decoder.decode(value, { stream: true });
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
}

export async function boundedJson(response: Response, limit: number): Promise<unknown> {
  if (!response.body) throw new Error('Empty body');
  return JSON.parse(await boundedText(response.body, limit));
}

export async function sendSlack(value: string, text: string) {
  const url = webhookUrl(value);
  if (!url) return { ok: false, retry: false, result: 'invalid_webhook' };
  try {
    const response = await fetch(url, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(8000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, unfurl_links: false, unfurl_media: false })
    });
    await response.body?.cancel();
    const delay = Number(response.headers.get('Retry-After')) * 1000;
    return { ok: response.status === 200, retry: response.status === 429 || response.status >= 500,
      result: 'slack_http_' + response.status, delay: Number.isFinite(delay) ? Math.min(delay, 86_400_000) : 0 };
  } catch {
    return { ok: false, retry: true, result: 'slack_network_error' };
  }
}
