import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { MessageInspector } from '../protocol/inspector.js';
import { ContractRecorder } from '../contracts/contract.js';
import { SseObserver } from '../protocol/sse-parser.js';
import { log, logError } from '../observability/logger.js';

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

function filterHopHeaders(headers) {
  const connectionTokens = String(headers.connection || '')
    .split(',').map((token) => token.trim().toLowerCase()).filter(Boolean);
  const blocked = new Set([...HOP_BY_HOP, ...connectionTokens]);
  return Object.fromEntries(Object.entries(headers).filter(([name, value]) =>
    value !== undefined && !blocked.has(name.toLowerCase())));
}

function normalizeHostname(host) {
  return String(host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

function isLoopback(host) {
  return ['127.0.0.1', '::1', 'localhost'].includes(normalizeHostname(host));
}

function hostHeaderHostname(value) {
  if (typeof value !== 'string' || value.length > 512 || /[\r\n\s/@]/.test(value)) return '';
  try {
    return normalizeHostname(new URL(`http://${value}`).hostname);
  } catch {
    return '';
  }
}

function originIsAllowed(origin, { localOnly, allowedOrigins }) {
  if (typeof origin !== 'string' || origin.length > 2048 || origin === 'null') return false;
  let parsed;
  try { parsed = new URL(origin); } catch { return false; }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.origin !== origin) return false;
  if (allowedOrigins.size > 0) return allowedOrigins.has(origin);
  return localOnly && isLoopback(parsed.hostname);
}

function rejectRequest(outgoing, reason) {
  log('warn', 'http.request_rejected', { reason });
  outgoing.writeHead(403, {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': '9',
    'x-content-type-options': 'nosniff',
  });
  outgoing.end('Forbidden');
}

function inspectJsonBody(inspector, chunks, totalBytes, maxBytes) {
  if (totalBytes === 0) return;
  if (totalBytes > maxBytes) {
    log('warn', 'http.inspect_skipped', { reason: 'body_limit', bytes: totalBytes, max_bytes: maxBytes });
    return;
  }
  void inspector.observeFrame(Buffer.concat(chunks, totalBytes)).catch(() => {
    log('warn', 'rpc.inspection_failed', { transport: 'http' });
  });
}

export function startHttpProxy({ upstream, listen = '127.0.0.1:9900', allowRemote = false, contractFile, contractSource, updateContract = false } = {}) {
  if (!upstream) throw new Error('--upstream is required for HTTP proxy mode');
  const upstreamUrl = new URL(upstream);
  const configuredToken = process.env.MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN;
  if (configuredToken && !/^[A-Za-z0-9._~+\/-]+=*$/.test(configuredToken)) throw new Error('MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN contains unsupported header characters');
  if (configuredToken && upstreamUrl.protocol !== 'https:' && !isLoopback(upstreamUrl.hostname)) throw new Error('Bearer credentials require HTTPS for non-loopback upstreams');
  if (!['http:', 'https:'].includes(upstreamUrl.protocol)) throw new Error('Upstream must use http:// or https://');
  if (upstreamUrl.username || upstreamUrl.password) throw new Error('Credentials in upstream URLs are not allowed; use environment variables');
  const [listenHostRaw, listenPortRaw] = splitListen(listen);
  const listenHost = listenHostRaw || '127.0.0.1';
  const listenPort = Number(listenPortRaw || 9900);
  if (!Number.isInteger(listenPort) || listenPort < 0 || listenPort > 65535) throw new Error('Invalid listen port');
  const localOnly = isLoopback(listenHost);
  if (!localOnly && !allowRemote) {
    throw new Error('Non-loopback binds require --allow-remote. Add an authenticated gateway before exposing this proxy.');
  }
  const allowedOrigins = new Set(String(process.env.MCP_INSPECTOR_ALLOWED_ORIGINS || '')
    .split(',').map((value) => value.trim()).filter(Boolean));
  for (const origin of allowedOrigins) {
    if (!originIsAllowed(origin, { localOnly: false, allowedOrigins: new Set([origin]) })) {
      throw new Error('MCP_INSPECTOR_ALLOWED_ORIGINS must contain canonical http:// or https:// origins without paths or credentials');
    }
  }

  const contractRecorder = new ContractRecorder({ path: contractFile, source: contractSource || upstreamUrl.origin, update: updateContract });
  let requestSequence = 0;
  const sessionPendingStores = new Map();
  const maxSessionStores = 256;
  const configuredMaxBytes = Number(process.env.MCP_INSPECTOR_MAX_FRAME_BYTES ?? 16 * 1024 * 1024);
  const maxInspectBytes = Number.isSafeInteger(configuredMaxBytes) && configuredMaxBytes >= 1024
    ? configuredMaxBytes
    : 16 * 1024 * 1024;

  const server = createServer((incoming, outgoing) => {
    const requestHostname = hostHeaderHostname(incoming.headers.host);
    if (localOnly && (!requestHostname || !isLoopback(requestHostname))) {
      incoming.resume();
      rejectRequest(outgoing, 'invalid_host');
      return;
    }
    const origin = incoming.headers.origin;
    if (origin !== undefined && !originIsAllowed(origin, { localOnly, allowedOrigins })) {
      incoming.resume();
      rejectRequest(outgoing, 'origin_not_allowed');
      return;
    }
    const corsHeaders = origin ? {
      'access-control-allow-origin': origin,
      'vary': 'Origin',
    } : {};
    if (incoming.method === 'OPTIONS' && incoming.headers['access-control-request-method']) {
      const requestedMethod = String(incoming.headers['access-control-request-method']).toUpperCase();
      const allowedMethods = new Set(['GET', 'POST', 'DELETE', 'OPTIONS']);
      const requestedHeaders = String(incoming.headers['access-control-request-headers'] || '')
        .split(',').map((header) => header.trim().toLowerCase()).filter(Boolean);
      const allowedHeaders = new Set([
        'authorization', 'content-type', 'accept', 'mcp-protocol-version',
        'mcp-session-id', 'last-event-id', 'if-none-match', 'if-match',
      ]);
      if (!allowedMethods.has(requestedMethod) || requestedHeaders.some((header) => !allowedHeaders.has(header))) {
        incoming.resume();
        rejectRequest(outgoing, 'preflight_not_allowed');
        return;
      }
      incoming.resume();
      outgoing.writeHead(204, {
        ...corsHeaders,
        'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS',
        'access-control-allow-headers': [...allowedHeaders].join(', '),
        'access-control-max-age': '600',
        'cache-control': 'no-store',
      });
      outgoing.end();
      return;
    }
    let target;
    try {
      target = new URL(incoming.url || '/', upstreamUrl.origin);
    } catch {
      outgoing.writeHead(400, { ...corsHeaders, 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      outgoing.end('Bad request URL');
      return;
    }
    if (target.origin !== upstreamUrl.origin) {
      outgoing.writeHead(400, { ...corsHeaders, 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      outgoing.end('Request target must remain on configured upstream origin');
      return;
    }

    // JSON-RPC identifiers are scoped to a connection/session. Modern stateless
    // requests are correlated within each HTTP exchange; legacy session headers
    // provide a stable scope for server-sent follow-up messages.
    requestSequence += 1;
    const rawSessionHeader = incoming.headers['mcp-session-id'];
    const sessionHeader = typeof rawSessionHeader === 'string' && rawSessionHeader.length <= 512 ? rawSessionHeader : undefined;
    const correlationScope = sessionHeader ? `session:${sessionHeader}` : `http:${requestSequence}`;
    let sessionState;
    if (sessionHeader) {
      const idleMsRaw = Number(process.env.MCP_INSPECTOR_SESSION_IDLE_MS ?? 1_800_000);
      const idleMs = Number.isSafeInteger(idleMsRaw) && idleMsRaw >= 60_000 && idleMsRaw <= 86_400_000 ? idleMsRaw : 1_800_000;
      const now = Date.now();
      for (const [key, value] of sessionPendingStores) {
        if (now - value.lastUsed > idleMs) {
          value.flushPending?.('session_idle_expired');
          sessionPendingStores.delete(key);
        }
      }
      sessionState = sessionPendingStores.get(sessionHeader);
      if (!sessionState) {
        while (sessionPendingStores.size >= maxSessionStores) {
          const oldest = sessionPendingStores.keys().next().value;
          const evicted = sessionPendingStores.get(oldest);
          evicted?.flushPending?.('session_store_limit');
          sessionPendingStores.delete(oldest);
        }
        sessionState = { pendingStore: new Map(), lastUsed: now, flushPending: null };
        sessionPendingStores.set(sessionHeader, sessionState);
      }
      sessionState.lastUsed = now;
    }
    const pendingStore = sessionState?.pendingStore ?? new Map();
    const ingressInspector = new MessageInspector({
      direction: 'client_to_server', transport: 'http', contractFile,
      contractSource: contractSource || upstreamUrl.origin, updateContract,
      pendingStore, contractRecorder, correlationScope, contractScope: upstreamUrl.origin,
      externalTraceId: incoming.headers.traceparent,
    });
    const egressInspector = new MessageInspector({
      direction: 'server_to_client', transport: 'http', contractFile,
      contractSource: contractSource || upstreamUrl.origin, updateContract,
      pendingStore, contractRecorder, correlationScope, contractScope: upstreamUrl.origin,
    });
    if (sessionState) sessionState.flushPending = (reason) => egressInspector.flushPending(reason);

    const headers = filterHopHeaders(incoming.headers);
    headers.host = target.host;
    headers.connection = 'keep-alive';
    const token = process.env.MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN;
    if (token) headers.authorization = `Bearer ${token}`;
    const requestFn = target.protocol === 'https:' ? httpsRequest : httpRequest;
    const upstreamReq = requestFn(target, { method: incoming.method, headers }, (upstreamRes) => {
      const responseHeaders = filterHopHeaders(upstreamRes.headers);
      responseHeaders['cache-control'] = responseHeaders['cache-control'] || 'no-store';
      if (corsHeaders.vary) {
        const varyValues = new Set(String(responseHeaders.vary || '').split(',').map((value) => value.trim()).filter(Boolean));
        varyValues.add('Origin');
        responseHeaders.vary = [...varyValues].join(', ');
      }
      outgoing.writeHead(upstreamRes.statusCode || 502, { ...responseHeaders, ...corsHeaders });
      upstreamRes.on('error', (error) => {
        logError('http.upstream_response_error', error, { method: incoming.method, path: safePath(incoming.url) });
        if (!outgoing.destroyed) outgoing.destroy();
      });
      // Forward the response stream before doing any side-channel parsing.
      upstreamRes.pipe(outgoing);
      const contentType = String(upstreamRes.headers['content-type'] || '').toLowerCase();
      // MCP SSE responses can remain open while idle; don't apply the ordinary
      // upstream inactivity deadline after an event stream has been established.
      if (contentType.includes('text/event-stream')) upstreamReq.setTimeout(0);
      const responseEncoding = String(upstreamRes.headers['content-encoding'] || 'identity').toLowerCase();
      const canInspectResponse = responseEncoding === 'identity' || responseEncoding === '';
      let totalBytes = 0;
      const responseChunks = [];
      let inspectorDisabled = false;
      const sseObserver = canInspectResponse && contentType.includes('text/event-stream')
        ? new SseObserver((frame) => {
          void egressInspector.observeFrame(frame).catch(() => {
            log('warn', 'rpc.inspection_failed', { transport: 'http', direction: 'server_to_client' });
          });
        }, {
          maxEventBytes: maxInspectBytes,
          onOversize: () => log('warn', 'http.sse_event_oversize', { max_bytes: maxInspectBytes }),
        })
        : undefined;
      upstreamRes.on('data', (chunk) => {
        totalBytes += chunk.length;
        if (sseObserver) {
          sseObserver.push(chunk);
        } else if (canInspectResponse && contentType.includes('application/json') && !inspectorDisabled) {
          if (totalBytes > maxInspectBytes) {
            inspectorDisabled = true;
            responseChunks.length = 0;
            log('warn', 'http.inspect_skipped', { reason: 'response_body_limit', max_bytes: maxInspectBytes });
          } else {
            responseChunks.push(chunk);
          }
        }
      });
      upstreamRes.on('end', () => {
        if (sseObserver) sseObserver.end();
        else if (canInspectResponse && contentType.includes('application/json') && !inspectorDisabled) inspectJsonBody(egressInspector, responseChunks, totalBytes, maxInspectBytes);
        if (!sessionHeader) egressInspector.flushPending('http_exchange_ended');
        log('debug', 'http.response_forwarded', { status_code: upstreamRes.statusCode || 0, bytes: totalBytes, content_type: contentType.split(';')[0] || 'unknown' });
      });
    });

    const timeoutRaw = Number(process.env.MCP_INSPECTOR_UPSTREAM_TIMEOUT_MS ?? 120_000);
    const upstreamTimeoutMs = Number.isSafeInteger(timeoutRaw) && timeoutRaw >= 1_000 && timeoutRaw <= 3_600_000 ? timeoutRaw : 120_000;
    upstreamReq.setTimeout(upstreamTimeoutMs, () => {
      log('warn', 'http.upstream_timeout', { timeout_ms: upstreamTimeoutMs, method: incoming.method, path: safePath(incoming.url) });
      upstreamReq.destroy(new Error('Upstream inactivity timeout'));
    });
    upstreamReq.on('error', (error) => {
      logError('http.upstream_error', error, { method: incoming.method, path: safePath(incoming.url) });
      if (!outgoing.headersSent) outgoing.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      if (!outgoing.destroyed) outgoing.end('MCP upstream unavailable');
    });
    outgoing.on('close', () => {
      if (!upstreamReq.destroyed && !upstreamReq.writableEnded) upstreamReq.destroy();
    });
    // Register the byte-forwarding pipe before side-channel inspection listeners.
    incoming.pipe(upstreamReq);

    const requestContentType = String(incoming.headers['content-type'] || '').toLowerCase();
    const requestEncoding = String(incoming.headers['content-encoding'] || 'identity').toLowerCase();
    const requestChunks = [];
    let requestBytes = 0;
    let requestInspectDisabled = false;
    if ((requestEncoding === 'identity' || requestEncoding === '') && requestContentType.includes('application/json')) {
      incoming.on('data', (chunk) => {
        requestBytes += chunk.length;
        if (requestBytes > maxInspectBytes) {
          requestInspectDisabled = true;
          requestChunks.length = 0;
        } else if (!requestInspectDisabled) {
          requestChunks.push(chunk);
        }
      });
      incoming.on('end', () => {
        if (!requestInspectDisabled) inspectJsonBody(ingressInspector, requestChunks, requestBytes, maxInspectBytes);
        else log('warn', 'http.inspect_skipped', { reason: 'request_body_limit', bytes: requestBytes, max_bytes: maxInspectBytes });
      });
    }

  });

  server.on('close', () => {
    for (const state of sessionPendingStores.values()) state.flushPending?.('proxy_closed');
    sessionPendingStores.clear();
  });

  server.requestTimeout = 300_000;
  server.headersTimeout = 60_000;
  server.keepAliveTimeout = 5_000;
  server.listen(listenPort, listenHost, () => {
    const address = server.address();
    const actualPort = address && typeof address === 'object' ? address.port : listenPort;
    log(isLoopback(listenHost) ? 'info' : 'warn', 'proxy.started', {
      transport: 'http',
      listen: `${listenHost}:${actualPort}`,
      upstream: upstreamUrl.origin,
      remote_bind_allowed: allowRemote,
    });
  });

  const close = () => new Promise((resolve) => {
    server.close(() => resolve());
    // Shutdown must not wait forever for long-lived SSE clients.
    server.closeAllConnections?.();
  });
  return { server, close };
}

function splitListen(value) {
  const trimmed = String(value || '127.0.0.1:9900');
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']');
    if (end === -1) throw new Error('Invalid IPv6 listen address');
    return [trimmed.slice(1, end), trimmed.slice(end + 1).replace(/^:/, '')];
  }
  const separator = trimmed.lastIndexOf(':');
  if (separator === -1) return [trimmed, '9900'];
  return [trimmed.slice(0, separator) || '127.0.0.1', trimmed.slice(separator + 1)];
}

function safePath(path) {
  const value = String(path || '/');
  try {
    const parsed = new URL(value, 'http://localhost');
    return `${parsed.pathname}${parsed.search ? '?[query]' : ''}`.slice(0, 240);
  } catch {
    return '/[invalid]';
  }
}
