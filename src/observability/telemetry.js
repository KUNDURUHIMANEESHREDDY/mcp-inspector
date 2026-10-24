let api;
let sdk;
let initializationAttempted = false;

const NOOP_SPAN = Object.freeze({
  setAttribute() {},
  setStatus() {},
  recordException() {},
  end() {},
});

const SAFE_TRACEPARENT = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/i;

export function isValidTraceparent(value) {
  const match = typeof value === 'string' ? SAFE_TRACEPARENT.exec(value) : null;
  return Boolean(match && !/^0{32}$/i.test(match[1]) && !/^0{16}$/i.test(match[2]));
}

export function isSafeExternalTraceId(value) {
  if (isValidTraceparent(value)) return true;
  if (typeof value !== 'string') return false;
  const isHexId = /^[0-9a-f]{16,64}$/i.test(value);
  const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
  const candidate = isUuid ? value.replaceAll('-', '') : value;
  return (isHexId || isUuid) && !/^0+$/.test(candidate);
}

export async function initializeTelemetry() {
  if (initializationAttempted) return;
  initializationAttempted = true;

  // Keep the transparent proxy and its unit tests usable without optional
  // telemetry packages. The production package declares these dependencies;
  // absent dependencies degrade to no-op spans without affecting protocol IO.
  try {
    api = await import('@opentelemetry/api');
  } catch {
    return;
  }

  const traceEndpoint = process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT;
  const commonEndpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (!traceEndpoint && !commonEndpoint) return;

  try {
    const [{ NodeSDK }, { OTLPTraceExporter }] = await Promise.all([
      import('@opentelemetry/sdk-node'),
      import('@opentelemetry/exporter-trace-otlp-http'),
    ]);
    const exporterOptions = traceEndpoint ? { url: traceEndpoint } : {};
    sdk = new NodeSDK({ traceExporter: new OTLPTraceExporter(exporterOptions) });
    await sdk.start();
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      time: new Date().toISOString(),
      level: 'warn',
      event: 'otel.initialization_failed',
      error_type: error?.name ?? 'Error',
    })}\n`);
  }
}

export function startRpcSpan({ method, tool, requestId, externalTraceId, transport }) {
  if (!api) return NOOP_SPAN;

  const tracer = api.trace.getTracer('mcp-inspector', '0.1.0');
  const isTraceparent = isValidTraceparent(externalTraceId);
  const extracted = isTraceparent
    ? api.propagation.extract(api.context.active(), { traceparent: externalTraceId })
    : api.context.active();

  return tracer.startSpan(`mcp.${method || 'unknown'}`, {
    attributes: {
      'rpc.system': 'jsonrpc',
      'rpc.service': 'mcp',
      'rpc.method': method || 'unknown',
      'mcp.request.id': String(requestId).slice(0, 128),
      'mcp.transport': transport || 'unknown',
      ...(tool ? { 'mcp.tool.name': String(tool).slice(0, 128) } : {}),
      ...(isSafeExternalTraceId(externalTraceId) ? { 'mcp.external_trace_id': externalTraceId } : {}),
    },
  }, extracted);
}

export function finishRpcSpan(span, { durationMs, isError = false, errorCode } = {}) {
  if (!span) return;
  if (Number.isFinite(durationMs)) span.setAttribute('mcp.duration_ms', durationMs);
  if (errorCode !== undefined && errorCode !== null) span.setAttribute('mcp.error.code', String(errorCode));
  if (isError && api) span.setStatus({ code: api.SpanStatusCode.ERROR });
  span.end();
}

export async function shutdownTelemetry() {
  if (sdk) {
    try {
      await sdk.shutdown();
    } catch {
      // Never corrupt MCP stdout if the exporter cannot flush during shutdown.
    }
  }
}
