import { createServer } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { Resolver } from 'node:dns/promises';
import { connect } from 'node:tls';
import ipaddr from 'ipaddr.js';
import { normalizeHost } from '../src/core.ts';

const token = process.env.SCANNER_TOKEN;
if (!token || token.length < 32) throw new Error('Set SCANNER_TOKEN to a random secret of at least 32 characters.');
const digest = value => createHash('sha256').update(value).digest();
const expected = digest('Bearer ' + token);

function publicIPv4(value) {
  return ipaddr.IPv4.isValidFourPartDecimal(value) &&
    ipaddr.IPv4.parse(value).range() === 'unicast';
}

async function scan(hostname) {
  const resolver = new Resolver({ timeout: 1500, tries: 2 });
  const addresses = await resolver.resolve4(hostname + '.').catch(() => []);
  const address = addresses.find(publicIPv4);
  if (!address) return { status: 'no_public_address' };

  return new Promise(resolve => {
    const socket = connect({ host: address, servername: hostname, port: 443, rejectUnauthorized: false });
    const finish = result => {
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };
    const timer = setTimeout(() => finish({ status: 'tls_unreachable' }), 4000);
    socket.once('error', () => finish({ status: 'tls_unreachable' }));
    socket.once('secureConnect', () => {
      const date = Date.parse(socket.getPeerCertificate().valid_to);
      finish(Number.isFinite(date)
        ? { status: socket.authorized ? 'ok' : 'tls_untrusted', expiry: new Date(date).toISOString() }
        : { status: 'tls_unreachable' });
    });
  });
}

let active = 0;
const server = createServer({ requestTimeout: 10_000, headersTimeout: 5000 }, async (req, res) => {
  const reply = (status, data) => {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(data));
  };
  if (req.method !== 'POST' || req.url !== '/check') return reply(404, {});
  if (!timingSafeEqual(expected, digest(req.headers.authorization ?? ''))) return reply(401, {});
  if (active >= 12) return reply(429, {});
  active++;
  try {
    let length = 0;
    const chunks = [];
    for await (const chunk of req) {
      length += chunk.length;
      if (length > 1024) {
        req.destroy();
        return;
      }
      chunks.push(chunk);
    }
    const parsed = normalizeHost(JSON.parse(Buffer.concat(chunks).toString())?.hostname);
    if (!parsed) return reply(400, {});
    reply(200, { hostname: parsed.hostname, ...await scan(parsed.hostname) });
  } catch {
    reply(400, {});
  } finally {
    active--;
  }
});
server.setTimeout(10_000, socket => socket.destroy());
server.listen(Number(process.env.PORT ?? 9090), process.env.BIND_HOST ?? '127.0.0.1');
