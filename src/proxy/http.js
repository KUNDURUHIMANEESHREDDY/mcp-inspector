import { timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { lookup as dnsLookup } from 'node:dns';
import { isIP } from 'node:net';
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

function inIpv4Range(address, network, prefix) {
  const value = address.split('.').reduce((acc, part) => ((acc * 256) + Number(part)) >>> 0, 0);
  const base = network.split('.').reduce((acc, part) => ((acc * 256) + Number(part)) >>> 0, 0);
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) >>> 0 === (base & mask) >>> 0;
}

/** True for special-use / private addresses which must not be targeted implicitly. */
export function isRestrictedUpstreamAddress(address) {
  const clean = String(address || '').toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  const family = isIP(clean);
  if (family === 4) {
    const ranges = [
      ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
      ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
      ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
      ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
    ];
    return ranges.some(([network, prefix]) => inIpv4Range(clean, network, prefix));
  }
  if (family === 6) {
    const value = ipv6ToBigInt(clean);
    if (value === null) return true;

    // IPv4-mapped IPv6 addresses must inherit the embedded IPv4 policy. This
    // is representation-independent, so expanded forms cannot bypass checks.
    if ((value >> 32n) === 0xffffn) {
      const embedded = Number(value & 0xffffffffn);
      return isRestrictedUpstreamAddress([
        (embedded >>> 24) & 255,
        (embedded >>> 16) & 255,
        (embedded >>> 8) & 255,
        embedded & 255,
      ].join('.'));
    }

    // Only global-unicast IPv6 is eligible for implicit upstream access.
    // Several special-use ranges sit inside 2000::/3, so the broad global
    // prefix check is followed by explicit IANA special-use exclusions.
    if (!ipv6InRange(value, '2000::', 3)) return true;
    const specialUseRanges = [
      ['2001::', 23],       // IETF protocol assignments
      ['2001:db8::', 32],   // Documentation
      ['2002::', 16],       // Deprecated 6to4
      ['3fff::', 20],       // Documentation
    ];
    return specialUseRanges.some(([network, prefix]) => ipv6InRange(value, network, prefix));
  }
  return true;
}


function ipv6ToBigInt(address) {
  let input = String(address || '').toLowerCase().split('%')[0];
  if (isIP(input) !== 6) return null;

  // Convert an IPv4 dotted tail into its two hexadecimal words before
  // expanding ::, so mapped addresses share one canonical numeric path.
  if (input.includes('.')) {
    const splitAt = input.lastIndexOf(':');
    const ipv4 = input.slice(splitAt + 1);
    if (isIP(ipv4) !== 4) return null;
    const octets = ipv4.split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    input = input.slice(0, splitAt + 1) + high + ':' + low;
  }

  const halves = input.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const words = [...left, ...Array(missing).fill('0'), ...right].map((word) => Number.parseInt(word, 16));
  if (words.length !== 8 || words.some((word) => !Number.isInteger(word) || word < 0 || word > 0xffff)) return null;
  return words.reduce((result, word) => (result << 16n) | BigInt(word), 0n);
}

function ipv6InRange(value, network, prefix) {
  const base = ipv6ToBigInt(network);
  if (base === null) return true;
  const shift = BigInt(128 - prefix);
  return (value >> shift) === (base >> shift);
}

function parseAllowedUpstreamHosts(raw) {
  const hosts = new Set();
  const source = String(raw || '');
  const entries = source.split(',');
  // Treat a malformed allowlist as a configuration error instead of silently
  // dropping empty entries and changing the operator's intended trust boundary.
  if (source.trim() && entries.some((entry) => !entry.trim())) {
    throw new Error('MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS must not contain empty entries');
  }
  for (const value of entries.map((entry) => entry.trim()).filter(Boolean)) {
    const host = normalizeHostname(value);
    const validIp = isIP(host) !== 0;
    const validDns = host.length <= 253 && /^[a-z0-9.-]+$/i.test(host) &&
      !host.startsWith('.') && !host.endsWith('.') &&
      host.split('.').every((label) => label.length > 0 && label.length <= 63 && !label.startsWith('-') && !label.endsWith('-'));
    if (!validIp && !validDns) {
      throw new Error('MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS must be a comma-separated exact hostname/IP allowlist without ports or wildcards');
    }
    hosts.add(host);
  }
  return hosts;
}

function createSafeUpstreamLookup(allowedHosts) {
  return (hostname, options, callback) => {
    const lookupOptions = typeof options === 'object' && options !== null ? options : {};
    const done = typeof options === 'function' ? options : callback;
    dnsLookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
      if (error) return done(error);
      if (!Array.isArray(addresses) || addresses.length === 0) return done(new Error('Upstream host did not resolve'));
      const normalized = normalizeHostname(hostname);
      const explicitlyTrusted = isLoopback(normalized) || allowedHosts.has(normalized);
      if (!explicitlyTrusted && addresses.some((item) => isRestrictedUpstreamAddress(item.address))) {
        const blocked = new Error('Upstream hostname resolved to a private or special-use address; add its exact hostname to MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS only if trusted');
        blocked.code = 'ERR_MCP_INSPECTOR_UPSTREAM_ADDRESS_BLOCKED';
        return done(blocked);
      }
      const matchingFamily = lookupOptions.family
        ? addresses.filter((item) => item.family === lookupOptions.family)
        : addresses;
      if (matchingFamily.length === 0) return done(new Error('No upstream address matches the requested address family'));
      if (lookupOptions.all) return done(null, matchingFamily);
      return done(null, matchingFamily[0].address, matchingFamily[0].family);
    });
  };
}

function parseConfiguredUpstreamHeaders(raw, bearerToken) {
  if (!raw) return {};
  if (raw.length > 8192) throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS exceeds the 8 KiB configuration limit');
  let parsed;
  try { parsed = JSON.parse(raw); } catch { throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS must be a JSON object of header names to string values'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS must be a JSON object of header names to string values');
  }
  const result = {};
  const seen = new Set();
  const forbidden = new Set([...HOP_BY_HOP, 'host', 'content-length', 'proxy-authorization', 'proxy-authenticate']);
  const entries = Object.entries(parsed);
  if (entries.length > 32) throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS supports at most 32 headers');
  for (const [name, value] of entries) {
    if (!/^[A-Za-z0-9!#$%&'*+.^_|~-]+$/.test(name)) throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS contains an invalid header name');
    const key = name.toLowerCase();
    if (seen.has(key)) throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS contains duplicate header names');
    seen.add(key);
    if (forbidden.has(key)) throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS cannot override hop-by-hop, host, or content-length headers');
    if (key === 'authorization' && bearerToken) throw new Error('Set either MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN or an authorization header, not both');
    if (typeof value !== 'string' || value.length > 4096 || /[\r\n\u0000]/.test(value)) {
      throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS values must be strings up to 4096 characters without control line breaks');
    }
    result[key] = value;
  }
  return result;
}

function hostHeaderHostname(value) {
  // Host is an authority, not a URL. Reject URL delimiters and malformed
  // authority syntax before URL parsing so query/fragment text cannot be
  // silently discarded while the parsed hostname still appears loopback.
  if (typeof value !== 'string' || value.length > 512) return '';
  const authority = /^(?:\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.?)((?::([0-9]{1,5}))?)$/i;
  const match = authority.exec(value);
  if (!match || /[\r\n\s/@?#%\\]/.test(value)) return '';
  if (match[2] !== undefined && Number(match[2]) > 65535) return '';
  try {
    const parsed = new URL(`http://${value}`);
    if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) return '';
    const hostname = normalizeHostname(parsed.hostname);
    // WHATWG URL parsing normalizes legacy IPv4 forms such as 127.1 and
    // 0x7f000001 to 127.0.0.1. Do not let a non-IP spelling become a
    // loopback IP after parsing.
    const closeBracket = value.startsWith('[') ? value.indexOf(']') : -1;
    const rawHostname = closeBracket >= 0
      ? value.slice(1, closeBracket)
      : value.split(':')[0];
    if (isIP(rawHostname) === 0 && isIP(hostname) !== 0) return '';
    return hostname;
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

function rejectUnauthorized(outgoing) {
  log('warn', 'http.request_rejected', { reason: 'proxy_auth_required' });
  const body = 'Unauthorized';
  outgoing.writeHead(401, {
    'www-authenticate': 'Bearer realm="mcp-inspector"',
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body),
    'x-content-type-options': 'nosniff',
  });
  outgoing.end(body);
}

function hasValidBearerToken(header, expected) {
  if (typeof header !== 'string' || typeof expected !== 'string') return false;
  const match = /^Bearer ([A-Za-z0-9._~+\/-]+=*)$/i.exec(header);
  if (!match) return false;
  const actual = Buffer.from(match[1], 'utf8');
  const wanted = Buffer.from(expected, 'utf8');
  return actual.length === wanted.length && timingSafeEqual(actual, wanted);
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
  const configuredProxyToken = process.env.MCP_INSPECTOR_PROXY_BEARER_TOKEN;
  if (configuredToken && !/^[A-Za-z0-9._~+\/-]+=*$/.test(configuredToken)) throw new Error('MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN contains unsupported header characters');
  if (configuredToken && upstreamUrl.protocol !== 'https:' && !isLoopback(upstreamUrl.hostname)) throw new Error('Bearer credentials require HTTPS for non-loopback upstreams');
  if (!['http:', 'https:'].includes(upstreamUrl.protocol)) throw new Error('Upstream must use http:// or https://');
  if (upstreamUrl.username || upstreamUrl.password) throw new Error('Credentials in upstream URLs are not allowed; use environment variables');
  const allowedUpstreamHosts = parseAllowedUpstreamHosts(process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS);
  const safeUpstreamLookup = createSafeUpstreamLookup(allowedUpstreamHosts);
  const configuredHeaders = parseConfiguredUpstreamHeaders(process.env.MCP_INSPECTOR_UPSTREAM_HEADERS || '', configuredToken);
  const configuredHostname = normalizeHostname(upstreamUrl.hostname);
  if (!isLoopback(configuredHostname) && !allowedUpstreamHosts.has(configuredHostname) &&
      isIP(configuredHostname) !== 0 && isRestrictedUpstreamAddress(configuredHostname)) {
    throw new Error('Private or special-use IP upstreams require an exact entry in MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS');
  }
  const [listenHostRaw, listenPortRaw] = splitListen(listen);
  const listenHost = listenHostRaw || '127.0.0.1';
  const listenPort = Number(listenPortRaw || 9900);
  if (!Number.isInteger(listenPort) || listenPort < 0 || listenPort > 65535) throw new Error('Invalid listen port');
  const localOnly = isLoopback(listenHost);
  if (!localOnly && !allowRemote) {
    throw new Error('Non-loopback binds require --allow-remote. Add an authenticated gateway before exposing this proxy.');
  }
  const rawAllowedOrigins = String(process.env.MCP_INSPECTOR_ALLOWED_ORIGINS || '');
  const originEntries = rawAllowedOrigins.split(',').map((value) => value.trim());
  if (rawAllowedOrigins.trim() && originEntries.some((value) => !value)) {
    throw new Error('MCP_INSPECTOR_ALLOWED_ORIGINS must not contain empty entries');
  }
  const allowedOrigins = new Set(originEntries.filter(Boolean));
  for (const origin of allowedOrigins) {
    if (!originIsAllowed(origin, { localOnly: false, allowedOrigins: new Set([origin]) })) {
      throw new Error('MCP_INSPECTOR_ALLOWED_ORIGINS must contain canonical http:// or https:// origins without paths or credentials');
    }
  }
  if (!localOnly) {
    if (!configuredProxyToken || configuredProxyToken.length < 32) {
      throw new Error('Non-loopback binds require MCP_INSPECTOR_PROXY_BEARER_TOKEN with at least 32 characters');
    }
    if (!/^[A-Za-z0-9._~+\/-]+=*$/.test(configuredProxyToken)) {
      throw new Error('MCP_INSPECTOR_PROXY_BEARER_TOKEN contains unsupported header characters');
    }
    if (allowedOrigins.size === 0) {
      throw new Error('Non-loopback binds require MCP_INSPECTOR_ALLOWED_ORIGINS with at least one exact origin');
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
    if (!localOnly && !hasValidBearerToken(incoming.headers.authorization, configuredProxyToken)) {
      incoming.resume();
      rejectUnauthorized(outgoing);
      return;
    }
    // This is a reverse proxy for one configured upstream, not a forward
    // proxy. Accept origin-form request targets only; never construct the
    // outbound URL from a client-controlled absolute/network-path reference.
    const targetPath = incoming.url || '/';
    if (!targetPath.startsWith('/') || targetPath.startsWith('//') || /[\\#\u0000-\u001f\u007f]/.test(targetPath)) {
      incoming.resume();
      outgoing.writeHead(400, {
        ...corsHeaders,
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store',
        'content-length': '11',
        'x-content-type-options': 'nosniff',
      });
      outgoing.end('Bad request');
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
    // In remote mode Authorization authenticates the client to this proxy; do
    // not leak that credential to the upstream. Configure upstream credentials
    // separately with MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN/UPSTREAM_HEADERS.
    if (!localOnly) delete headers.authorization;
    Object.assign(headers, configuredHeaders);
    headers.host = upstreamUrl.host;
    headers.connection = 'keep-alive';
    const token = process.env.MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN;
    if (token) headers.authorization = `Bearer ${token}`;
    const requestFn = upstreamUrl.protocol === 'https:' ? httpsRequest : httpRequest;
    const upstreamReq = requestFn(upstreamUrl, { method: incoming.method, path: targetPath, headers, lookup: safeUpstreamLookup }, (upstreamRes) => {
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
  // Keep incomplete request headers bounded when the proxy is explicitly exposed remotely.
  server.headersTimeout = 15_000;
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
