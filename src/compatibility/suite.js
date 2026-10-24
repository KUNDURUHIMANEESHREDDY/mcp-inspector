import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { performance } from 'node:perf_hooks';
import { createContract, contractHash } from '../contracts/contract.js';
import { summarizeCompatibilityResults } from './engine.js';

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
  const message = String(error?.message ?? 'compatibility_probe_failed')
    .replace(/https?:\/\/[^\s]+/gi, '[endpoint]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, 'Bearer [REDACTED]')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .slice(0, 240);
  return { errorType: type, errorMessage: message };
}

async function runOne({ transport, protocol, command, args, url, timeoutMs, signal }) {
  const started = performance.now();
  const client = new Client({ name: 'mcp-inspector-compatibility-suite', version: '0.1.0' }, clientOptions(protocol));
  let connection;
  try {
    connection = transport === 'stdio'
      ? new StdioClientTransport({ command, args, env: { ...process.env, MCP_INSPECTOR_LOG_LEVEL: 'error' } })
      : new StreamableHTTPClientTransport(validateEndpoint(url));
    await withDeadline(client.connect(connection), timeoutMs, signal, 'connect');
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

/** Read-only initialize + tools/list compatibility probes; never invokes tools. */
export async function runCompatibilitySuite({
  transports = ['stdio'], protocols = ['legacy', 'auto', 'modern'], command, args = [], url,
  timeoutMs = 15_000, signal,
} = {}) {
  if (!Array.isArray(transports) || transports.length < 1 || transports.some((item) => !TRANSPORTS.has(item))) throw new TypeError('transports must contain stdio and/or http');
  if (!Array.isArray(protocols) || protocols.length < 1 || protocols.some((item) => !PROTOCOL_MODES.has(item))) throw new TypeError('protocols must contain legacy, auto, and/or modern');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) throw new RangeError('timeoutMs must be an integer from 100 to 120000');
  if (transports.includes('stdio') && (typeof command !== 'string' || command.length === 0)) throw new TypeError('stdio transport requires a server command');
  if (transports.includes('http')) validateEndpoint(url);
  const results = [];
  for (const transport of transports) {
    for (const protocol of protocols) {
      if (signal?.aborted) {
        results.push({ transport, requestedProtocol: protocol, status: 'cancelled', durationMs: 0, errorType: 'AbortError', errorMessage: 'Compatibility run cancelled' });
      } else {
        results.push(await runOne({ transport, protocol, command, args, url, timeoutMs, signal }));
      }
    }
  }
  return {
    schemaVersion: 1, generatedAt: new Date().toISOString(), readOnly: true,
    transports: [...transports], protocolModes: [...protocols], timeoutMs, results,
    summary: summarizeCompatibilityResults(results),
  };
}
