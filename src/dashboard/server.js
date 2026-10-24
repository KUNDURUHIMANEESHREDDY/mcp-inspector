import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { activateDashboardEventCapture, getDashboardEvents, getDashboardSummary, onDashboardEvent } from './event-store.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), 'ui');
const ASSETS = new Map([
  ['/', { file: 'index.html', type: 'text/html; charset=utf-8' }],
  ['/index.html', { file: 'index.html', type: 'text/html; charset=utf-8' }],
  ['/styles.css', { file: 'styles.css', type: 'text/css; charset=utf-8' }],
  ['/app.js', { file: 'app.js', type: 'text/javascript; charset=utf-8' }],
]);
const startedAt = new Date().toISOString();
const clients = new Set();

function isLoopback(host) {
  const value = String(host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  return value === '127.0.0.1' || value === '::1' || value === 'localhost';
}

function parseListen(value) {
  const input = String(value || '127.0.0.1:9911').trim();
  let host;
  let portText;
  if (input.startsWith('[')) {
    const close = input.indexOf(']');
    if (close < 0 || input[close + 1] !== ':') throw new Error('Dashboard listen must be host:port');
    host = input.slice(1, close);
    portText = input.slice(close + 2);
  } else {
    const split = input.lastIndexOf(':');
    if (split <= 0) throw new Error('Dashboard listen must be host:port');
    host = input.slice(0, split);
    portText = input.slice(split + 1);
  }
  const port = Number(portText);
  if (!isLoopback(host)) throw new Error('Dashboard is local-only and can bind only to loopback addresses');
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Dashboard port must be an integer from 0 to 65535');
  return { host, port };
}

function hostIsAllowed(value) {
  if (typeof value !== 'string' || value.length > 512 || !/^[A-Za-z0-9.\[\]:-]+$/.test(value)) return false;
  try {
    const parsed = new URL('http://' + value);
    return isLoopback(parsed.hostname) && !parsed.username && !parsed.password &&
      parsed.pathname === '/' && !parsed.search && !parsed.hash;
  } catch {
    return false;
  }
}

function originIsAllowed(value) {
  if (typeof value !== 'string' || value.length > 2048 || value === 'null') return false;
  try {
    const parsed = new URL(value);
    return ['http:', 'https:'].includes(parsed.protocol) &&
      parsed.origin === value && isLoopback(parsed.hostname) &&
      !parsed.username && !parsed.password;
  } catch {
    return false;
  }
}

function setSecurityHeaders(response) {
  response.setHeader('x-content-type-options', 'nosniff');
  response.setHeader('referrer-policy', 'no-referrer');
  response.setHeader('x-frame-options', 'DENY');
  response.setHeader('cache-control', 'no-store');
  response.setHeader('content-security-policy', "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'");
}

function sendJson(response, status, body) {
  const encoded = Buffer.from(JSON.stringify(body));
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': encoded.length });
  response.end(encoded);
}

function sendText(response, status, text) {
  const encoded = Buffer.from(text);
  response.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'content-length': encoded.length });
  response.end(encoded);
}

function sendSse(response, event) {
  return response.write('id: ' + event.id + '\nevent: inspector\ndata: ' + JSON.stringify(event) + '\n\n');
}

export async function startDashboardServer({ listen = '127.0.0.1:9911', version = '0.1.0' } = {}) {
  const binding = parseListen(listen);
  const server = createServer(async (request, response) => {
    setSecurityHeaders(response);
    if (!hostIsAllowed(request.headers.host)) {
      sendText(response, 403, 'Forbidden');
      return;
    }
    const origin = request.headers.origin;
    if (origin !== undefined && !originIsAllowed(origin)) {
      sendText(response, 403, 'Forbidden');
      return;
    }
    if (request.method !== 'GET') {
      response.setHeader('allow', 'GET');
      sendText(response, 405, 'Method not allowed');
      return;
    }

    let url;
    try {
      if (typeof request.url !== 'string' || request.url.length > 8192) throw new Error('bad url');
      url = new URL(request.url, 'http://localhost');
    } catch {
      sendText(response, 400, 'Bad request');
      return;
    }

    if (url.pathname === '/api/status') {
      sendJson(response, 200, {
        ok: true,
        version,
        startedAt,
        uptimeSeconds: Math.floor(process.uptime()),
        summary: getDashboardSummary(),
        capabilities: {
          liveEvents: true,
          payloadCapture: false,
          remoteBinding: false,
          clientSideReportImport: true,
        },
      });
      return;
    }

    if (url.pathname === '/api/events') {
      const rawLimit = Number(url.searchParams.get('limit') || 250);
      const rawAfter = Number(url.searchParams.get('after') || 0);
      if (!Number.isSafeInteger(rawLimit) || rawLimit < 1 || rawLimit > 500 ||
          !Number.isSafeInteger(rawAfter) || rawAfter < 0) {
        sendJson(response, 400, { error: 'limit must be 1-500 and after must be a non-negative integer' });
        return;
      }
      const events = getDashboardEvents({ limit: rawLimit, afterId: rawAfter });
      sendJson(response, 200, {
        events,
        summary: getDashboardSummary(),
        oldestId: events.length ? events[0].id : null,
        newestId: events.length ? events[events.length - 1].id : null,
      });
      return;
    }

    if (url.pathname === '/api/stream') {
      if (clients.size >= 8) {
        sendText(response, 503, 'Too many dashboard event streams');
        return;
      }
      const lastIdHeader = request.headers['last-event-id'];
      const lastId = typeof lastIdHeader === 'string' && /^\d{1,16}$/.test(lastIdHeader)
        ? Number(lastIdHeader)
        : 0;
      const replay = getDashboardEvents({ limit: 250, afterId: lastId });
      response.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache, no-transform',
        connection: 'keep-alive',
        'x-accel-buffering': 'no',
      });
      response.flushHeaders?.();
      clients.add(response);
      response.write('retry: 2000\n\n');
      for (const event of replay) {
        if (!sendSse(response, event)) {
          clients.delete(response);
          response.destroy();
          return;
        }
      }
      const unsubscribe = onDashboardEvent((event) => {
        if (!sendSse(response, event)) {
          unsubscribe();
          clearInterval(heartbeat);
          clients.delete(response);
          response.destroy();
        }
      });
      const heartbeat = setInterval(() => {
        if (!response.write(': heartbeat\n\n')) {
          unsubscribe();
          clearInterval(heartbeat);
          clients.delete(response);
          response.destroy();
        }
      }, 20000);
      heartbeat.unref?.();
      response.on('close', () => {
        unsubscribe();
        clearInterval(heartbeat);
        clients.delete(response);
      });
      return;
    }

    const asset = ASSETS.get(url.pathname);
    if (!asset) {
      sendText(response, 404, 'Not found');
      return;
    }
    try {
      const body = await readFile(join(ROOT, asset.file));
      response.writeHead(200, { 'content-type': asset.type, 'content-length': body.length });
      response.end(body);
    } catch {
      sendText(response, 500, 'Dashboard asset unavailable');
    }
  });

  server.requestTimeout = 10000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 5000;

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(binding.port, binding.host, () => {
      server.off('error', reject);
      resolve();
    });
  });

  const releaseEventCapture = activateDashboardEventCapture();
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    releaseEventCapture();
  };

  const address = server.address();
  const formattedHost = binding.host.includes(':') ? '[' + binding.host + ']' : binding.host;
  const actualPort = typeof address === 'object' && address ? address.port : binding.port;
  const url = 'http://' + formattedHost + ':' + actualPort;

  return {
    server,
    url,
    async close() {
      for (const client of clients) client.end();
      clients.clear();
      try {
        if (server.listening) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      } finally {
        release();
      }
    },
  };
}
