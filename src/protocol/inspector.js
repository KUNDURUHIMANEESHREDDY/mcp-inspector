import { performance } from 'node:perf_hooks';
import { LineFramer, decodeJsonRpcFrame, isJsonRpcMessage } from './framer.js';
import { ContractRecorder } from '../contracts/contract.js';
import { log, requestKey } from '../observability/logger.js';
import { finishRpcSpan, isSafeExternalTraceId, startRpcSpan } from '../observability/telemetry.js';

function externalTraceId(message, fallback) {
  const meta = message?._meta ?? message?.params?._meta ?? {};
  const candidates = [meta.traceparent, meta.trace_id, meta.traceId, meta['gen_ai.trace_id'], fallback];
  return candidates.find((candidate) => isSafeExternalTraceId(candidate));
}

function directionKey(direction) {
  return direction === 'client_to_server' ? 'client_to_server' : 'server_to_client';
}

export class MessageInspector {
  constructor({
    direction,
    transport = 'stdio',
    contractFile,
    contractSource,
    updateContract = false,
    maxFrameBytes,
    pendingStore,
    contractRecorder,
    correlationScope = 'default',
    contractScope = 'default',
    externalTraceId: transportTraceId,
  } = {}) {
    if (!['client_to_server', 'server_to_client'].includes(direction)) {
      throw new TypeError('direction must be client_to_server or server_to_client');
    }
    this.direction = direction;
    this.transport = transport;
    this.pending = pendingStore ?? new Map();
    this.correlationScope = correlationScope;
    this.contractScope = contractScope;
    this.externalTraceId = isSafeExternalTraceId(transportTraceId) ? transportTraceId : undefined;
    this.contractRecorder = contractRecorder ?? new ContractRecorder({
      path: contractFile,
      source: contractSource || 'mcp-server',
      update: updateContract,
    });
    this.framer = new LineFramer({
      maxFrameBytes: maxFrameBytes ?? readMaxFrameBytes(),
      onFrame: (frame) => {
        void this.observeFrame(frame).catch(() => {
          log('warn', 'rpc.inspection_failed', { direction: this.direction, transport: this.transport });
        });
      },
      onOversize: (details) => log('warn', 'rpc.frame_oversize', {
        direction: this.direction,
        transport: this.transport,
        ...details,
      }),
    });
  }

  push(chunk) {
    this.framer.push(chunk);
  }

  end() {
    this.framer.end();
  }

  flushPending(reason = 'transport_closed') {
    for (const [pendingKey, pending] of this.pending) {
      if (!pendingKey.startsWith(`${this.correlationScope}:`)) continue;
      clearTimeout(pending.timer);
      this.pending.delete(pendingKey);
      const durationMs = Number((performance.now() - pending.started).toFixed(3));
      finishRpcSpan(pending.span, { durationMs, isError: true });
      log('warn', 'rpc.pending_closed', {
        transport: this.transport,
        method: pending.method,
        request_id: pending.requestId,
        duration_ms: durationMs,
        reason,
      });
    }
  }

  async observeFrame(frame) {
    const decoded = decodeJsonRpcFrame(frame);
    if (!decoded.ok) {
      if (decoded.reason !== 'empty') {
        log('warn', 'rpc.frame_unparsed', {
          direction: this.direction,
          transport: this.transport,
          reason: decoded.reason,
          bytes: frame.length,
        });
      }
      return;
    }
    if (Array.isArray(decoded.value) || !isJsonRpcMessage(decoded.value)) {
      log('warn', 'rpc.invalid_envelope', { direction: this.direction, transport: this.transport, bytes: frame.length });
      return;
    }
    this.#observeMessage(decoded.value, frame.length);
  }

  #observeMessage(message, bytes) {
    const direction = this.direction;
    if (typeof message.method === 'string') {
      const method = message.method;
      const tool = method === 'tools/call' && typeof message.params?.name === 'string'
        ? message.params.name
        : undefined;
      if (!Object.hasOwn(message, 'id')) {
        log('debug', 'rpc.notification', { direction, transport: this.transport, method, ...(tool ? { tool } : {}), bytes });
        return;
      }

      const key = requestKey(message.id);
      // Request IDs can overlap when both ends initiate requests. Include the
      // origin direction in the map key, then correlate responses from the peer.
      const pendingKey = `${this.correlationScope}:${directionKey(direction)}:${key}`;
      const started = performance.now();
      const external = externalTraceId(message, this.externalTraceId);
      const span = startRpcSpan({ method, tool, requestId: key, externalTraceId: external, transport: this.transport });
      const maxPending = readMaxPendingRequests();
      const timeoutMs = readRpcTimeoutMs();
      const existing = this.pending.get(pendingKey);
      if (existing) {
        clearTimeout(existing.timer);
        finishRpcSpan(existing.span, {
          durationMs: Number((performance.now() - existing.started).toFixed(3)),
          isError: true,
        });
        log('warn', 'rpc.request_id_reused', { transport: this.transport, request_id: key, previous_method: existing.method });
      }
      while (!existing && this.pending.size >= maxPending) {
        const oldestKey = this.pending.keys().next().value;
        const evicted = this.pending.get(oldestKey);
        if (!evicted) break;
        clearTimeout(evicted.timer);
        finishRpcSpan(evicted.span, {
          durationMs: Number((performance.now() - evicted.started).toFixed(3)),
          isError: true,
        });
        this.pending.delete(oldestKey);
        log('warn', 'rpc.pending_evicted', { transport: this.transport, method: evicted.method, reason: 'pending_limit' });
      }
      const pendingEntry = {
        method,
        tool,
        started,
        span,
        params: message.params ?? {},
        externalTraceId: external,
        requestDirection: direction,
        requestId: key,
      };
      pendingEntry.timer = setTimeout(() => {
        if (this.pending.get(pendingKey) !== pendingEntry) return;
        this.pending.delete(pendingKey);
        const durationMs = Number((performance.now() - pendingEntry.started).toFixed(3));
        finishRpcSpan(pendingEntry.span, { durationMs, isError: true });
        log('warn', 'rpc.timeout', {
          transport: this.transport,
          method: pendingEntry.method,
          ...(pendingEntry.tool ? { tool: pendingEntry.tool } : {}),
          request_id: key,
          duration_ms: durationMs,
        });
      }, timeoutMs);
      pendingEntry.timer.unref?.();
      this.pending.set(pendingKey, pendingEntry);
      log(direction === 'client_to_server' ? 'info' : 'debug', direction === 'client_to_server' ? 'rpc.request' : 'rpc.reverse_request', {
        direction,
        transport: this.transport,
        method,
        ...(tool ? { tool } : {}),
        request_id: key,
        bytes,
        ...(external ? { external_trace_id_present: true } : {}),
      });
      return;
    }

    const key = requestKey(message.id);
    const oppositeDirection = direction === 'client_to_server' ? 'server_to_client' : 'client_to_server';
    const pendingKey = `${this.correlationScope}:${directionKey(oppositeDirection)}:${key}`;
    const pending = this.pending.get(pendingKey);
    if (!pending) {
      log('debug', 'rpc.response_unmatched', { direction, transport: this.transport, request_id: key, bytes });
      return;
    }
    clearTimeout(pending.timer);
    this.pending.delete(pendingKey);
    const durationMs = Number((performance.now() - pending.started).toFixed(3));
    const isError = Object.hasOwn(message, 'error') || message.result?.isError === true;
    const errorCode = message.error?.code;
    finishRpcSpan(pending.span, { durationMs, isError, errorCode });
    log(isError ? 'warn' : 'info', 'rpc.response', {
      direction,
      transport: this.transport,
      method: pending.method,
      ...(pending.tool ? { tool: pending.tool } : {}),
      request_id: key,
      duration_ms: durationMs,
      bytes,
      is_error: isError,
      ...(typeof errorCode === 'number' ? { error_code: errorCode } : {}),
    });

    if (pending.requestDirection === 'client_to_server' && pending.method === 'tools/list' && message.result) {
      void this.contractRecorder.observeToolsList(pending.params, message.result, this.contractScope).catch(() => {
        log('warn', 'contract.capture_failed', { transport: this.transport });
      });
    }
  }
}

export function readMaxFrameBytes() {
  const raw = Number(process.env.MCP_INSPECTOR_MAX_FRAME_BYTES ?? 16 * 1024 * 1024);
  return Number.isSafeInteger(raw) && raw >= 1024 ? raw : 16 * 1024 * 1024;
}

function readRpcTimeoutMs() {
  const raw = Number(process.env.MCP_INSPECTOR_RPC_TIMEOUT_MS ?? 120_000);
  return Number.isSafeInteger(raw) && raw >= 1_000 && raw <= 3_600_000 ? raw : 120_000;
}

function readMaxPendingRequests() {
  const raw = Number(process.env.MCP_INSPECTOR_MAX_PENDING_REQUESTS ?? 10_000);
  return Number.isSafeInteger(raw) && raw >= 1 && raw <= 100_000 ? raw : 10_000;
}
