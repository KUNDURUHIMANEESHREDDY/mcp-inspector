import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { performance } from 'node:perf_hooks';
import { createContract, contractHash } from '../contracts/contract.js';
import { summarizeCompatibilityResults } from './engine.js';
import { createOAuthContext } from './oauth-provider.js';

const PROTOCOL_MODES = new Set(['legacy', 'auto', 'modern']);
const TRANSPORTS = new Set(['stdio', 'http']);

function clientOptions(protocol) {
  if (protocol === 'auto') return { versionNegotiation: { mode: 'auto' } };
  if (protocol === 'modern') return { versionNegotiation: { mode: { pin: '2026-07-28' } } };
  return {};
}

function validateEndpoint(value) {
  let endpoint;
  try { endpoint = new URL(value); } catch { throw new TypeError('HTTP transport requires a valid absolute --url'); }
  if (!['http:', 'https:'].includes(endpoint.protocol)) throw new TypeError('HTTP endpoint must use http or https');
  if (endpoint.username || endpoint.password) throw new TypeError('Credentials in endpoint URLs are not allowed; use a protected environment or gateway');
  return endpoint;
}

function isLoopback(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

function getHttpHeaders(endpoint, oauth) {
  const token = process.env.MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN || '';
  const raw = process.env.MCP_INSPECTOR_UPSTREAM_HEADERS || '';
  if (oauth && token) throw new Error('Do not combine --oauth with MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN');
  if (token && endpoint.protocol !== 'https:' && !isLoopback(endpoint.hostname)) {
    throw new Error('Bearer credentials require HTTPS for non-loopback HTTP compatibility targets');
  }
  if (raw.length > 8192) throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS exceeds the 8 KiB configuration limit');
  let parsed = {};
  if (raw) {
    try { parsed = JSON.parse(raw); }
    catch { throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS must be a JSON object of header names to string values'); }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS must be a JSON object of header names to string values');
    }
  }
  const headers = {};
  const seen = new Set();
  const forbidden = new Set([
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length',
  ]);
  const entries = Object.entries(parsed);
  if (entries.length > 32) throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS supports at most 32 headers');
  for (const [name, value] of entries) {
    if (!/^[A-Za-z0-9!#$%&'*+.^_|~-]+$/.test(name)) throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS contains an invalid header name');
    const key = name.toLowerCase();
    if (seen.has(key)) throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS contains duplicate header names');
    seen.add(key);
    if (forbidden.has(key)) throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS cannot override hop-by-hop, host, or content-length headers');
    if (typeof value !== 'string' || value.length > 4096 || /[\r\n\u0000]/.test(value)) {
      throw new Error('MCP_INSPECTOR_UPSTREAM_HEADERS values must be strings up to 4096 characters without control line breaks');
    }
    if (oauth && key === 'authorization') throw new Error('Do not set an Authorization header in MCP_INSPECTOR_UPSTREAM_HEADERS when using --oauth');
    if (key === 'authorization' && token) throw new Error('Set either MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN or an authorization header, not both');
    if (endpoint.protocol !== 'https:' && !isLoopback(endpoint.hostname) &&
        (key === 'authorization' || key === 'cookie' || /token|secret|api.?key|auth|credential/i.test(key))) {
      throw new Error('Sensitive upstream headers require HTTPS for non-loopback HTTP compatibility targets');
    }
    headers[key] = value;
  }
  if (token) headers.authorization = 'Bearer ' + token;
  return headers;
}

function withDeadline(promise, timeoutMs, signal, label) {
  let timer;
  let abortHandler;
  const guards = [new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new Error(label + '_timeout');
      error.name = 'TimeoutError';
      reject(error);
    }, timeoutMs);
  })];
  if (signal) guards.push(new Promise((_, reject) => {
    abortHandler = () => {
      const error = new Error('Compatibility run cancelled');
      error.name = 'AbortError';
      reject(error);
    };
    if (signal.aborted) abortHandler();
    else signal.addEventListener('abort', abortHandler, { once: true });
  }));
  return Promise.race([promise, ...guards]).finally(() => {
    clearTimeout(timer);
    if (abortHandler && signal) signal.removeEventListener('abort', abortHandler);
  });
}

function safeError(error) {
  const type = typeof error?.name === 'string' ? error.name.slice(0, 80) : 'Error';
  const message = type === 'OAuthError'
    ? 'oauth_authorization_failed'
    : String(error?.message ?? 'compatibility_probe_failed')
      .replace(/https?:\/\/[^\s]+/gi, '[endpoint]')
      .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, 'Bearer [REDACTED]')
      .replace(/[\u0000-\u001f\u007f]/g, ' ')
      .slice(0, 240);
  return { errorType: type, errorMessage: message };
}

async function runOne({ transport, protocol, command, args, url, timeoutMs, signal, oauthContext, oauthTimeoutMs, httpHeaders }) {
  const started = performance.now();
  const client = new Client({ name: 'mcp-inspector-compatibility-suite', version: '0.1.0' }, clientOptions(protocol));
  let connection;
  const createConnection = () => transport === 'stdio'
    ? new StdioClientTransport({ command, args, env: { ...process.env, MCP_INSPECTOR_LOG_LEVEL: 'error' } })
    : new StreamableHTTPClientTransport(validateEndpoint(url), {
        requestInit: { headers: httpHeaders },
        ...(oauthContext ? { authProvider: oauthContext.provider } : {}),
      });
  try {
    connection = createConnection();
    try {
      await withDeadline(client.connect(connection), timeoutMs, signal, 'connect');
    } catch (error) {
      if (transport !== 'http' || !oauthContext || error?.name !== 'UnauthorizedError' || !oauthContext.provider.authorizationUrl) {
        throw error;
      }
      const params = await oauthContext.waitForCallback({ timeoutMs: oauthTimeoutMs, signal });
      if (params.get('state') !== oauthContext.provider.lastState) throw new Error('oauth_state_mismatch');
      await connection.finishAuth(params);
      connection = createConnection();
      await withDeadline(client.connect(connection), timeoutMs, signal, 'oauth_reconnect');
    }
    const listing = await withDeadline(client.listTools(), timeoutMs, signal, 'tools_list');
    if (!listing || !Array.isArray(listing.tools)) throw new Error('tools_list_invalid_result');
    const contract = createContract(listing.tools, transport === 'stdio' ? 'stdio-server' : 'http-server');
    const actualEra = client.getProtocolEra?.() ?? 'legacy-or-unknown';
    if (protocol === 'modern' && actualEra !== 'modern') throw new Error('modern_protocol_was_not_negotiated');
    if (protocol === 'legacy' && actualEra !== 'legacy') throw new Error('legacy_protocol_was_not_negotiated');
    const server = client.getServerVersion?.() ?? null;
    return {
      transport, requestedProtocol: protocol, negotiatedProtocol: actualEra, status: 'passed',
      durationMs: Number((performance.now() - started).toFixed(2)),
      toolCount: listing.tools.length, contractHash: contractHash(contract),
      authentication: transport === 'http' ? (oauthContext ? 'oauth' : (httpHeaders.authorization ? 'configured-header' : 'none')) : 'not-applicable',
      server: server && typeof server === 'object' ? {
        name: typeof server.name === 'string' ? server.name.slice(0, 100) : undefined,
        version: typeof server.version === 'string' ? server.version.slice(0, 80) : undefined,
      } : null,
    };
  } catch (error) {
    return {
      transport, requestedProtocol: protocol, negotiatedProtocol: null,
      status: error?.name === 'AbortError' ? 'cancelled' : 'failed',
      durationMs: Number((performance.now() - started).toFixed(2)),
      ...safeError(error),
    };
  } finally {
    try { await withDeadline(Promise.resolve(client.close()), 2_000, undefined, 'close'); }
    catch { try { await connection?.close?.(); } catch { /* Best-effort cleanup after a failed probe. */ } }
  }
}

/**
 * Run read-only initialization and tools/list checks; never invokes a tool.
 * When oauth=true, use the SDK's OAuth 2.1/PKCE discovery and exchange flow.
 */
export async function runCompatibilitySuite({
  transports = ['stdio'], protocols = ['legacy', 'auto', 'modern'], command, args = [], url,
  timeoutMs = 15_000, signal, oauth = false, oauthTimeoutMs = 300_000,
} = {}) {
  if (!Array.isArray(transports) || transports.length < 1 || transports.some((item) => !TRANSPORTS.has(item))) throw new TypeError('transports must contain stdio and/or http');
  if (!Array.isArray(protocols) || protocols.length < 1 || protocols.some((item) => !PROTOCOL_MODES.has(item))) throw new TypeError('protocols must contain legacy, auto, and/or modern');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) throw new RangeError('timeoutMs must be an integer from 100 to 120000');
  if (!Number.isInteger(oauthTimeoutMs) || oauthTimeoutMs < 30_000 || oauthTimeoutMs > 900_000) throw new RangeError('oauthTimeoutMs must be an integer from 30000 to 900000');
  if (transports.includes('stdio') && (typeof command !== 'string' || command.length === 0)) throw new TypeError('stdio transport requires a server command');
  if (transports.includes('http')) validateEndpoint(url);
  if (oauth && !transports.includes('http')) throw new TypeError('OAuth can only be used with the HTTP transport');

  const endpoint = transports.includes('http') ? validateEndpoint(url) : null;
  const httpHeaders = endpoint ? getHttpHeaders(endpoint, oauth) : {};
  if (oauth && endpoint.protocol !== 'https:' && !isLoopback(endpoint.hostname)) {
    throw new Error('Interactive OAuth requires HTTPS for non-loopback targets');
  }
  if (oauth && (httpHeaders.authorization || Object.keys(httpHeaders).some((key) => key === 'cookie'))) {
    throw new Error('OAuth cannot be combined with static Authorization or Cookie headers');
  }

  let oauthContext;
  const results = [];
  try {
    if (oauth) oauthContext = await createOAuthContext();
    for (const transport of transports) {
      for (const protocol of protocols) {
        if (signal?.aborted) {
          results.push({ transport, requestedProtocol: protocol, status: 'cancelled', durationMs: 0, errorType: 'AbortError', errorMessage: 'Compatibility run cancelled' });
          continue;
        }
        results.push(await runOne({
          transport, protocol, command, args, url, timeoutMs, signal, oauthContext, oauthTimeoutMs, httpHeaders,
        }));
      }
    }
    return {
      schemaVersion: 1, generatedAt: new Date().toISOString(), readOnly: true,
      transports: [...transports], protocolModes: [...protocols], timeoutMs,
      authentication: oauth ? 'oauth' : (httpHeaders.authorization ? 'configured-header' : (Object.keys(httpHeaders).length ? 'custom-headers' : 'none')),
      results, summary: summarizeCompatibilityResults(results),
    };
  } finally {
    await oauthContext?.close();
  }
}
