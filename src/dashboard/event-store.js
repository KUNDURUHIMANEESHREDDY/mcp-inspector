import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';

const MAX_EVENTS = 2000;
const emitter = new EventEmitter();
emitter.setMaxListeners(32);
const events = [];
let nextId = 1;
let totalPublished = 0;
let activeDashboardServers = 0;

const SAFE_FIELDS = new Set([
  'transport', 'direction', 'method', 'tool', 'request_id', 'bytes',
  'duration_ms', 'is_error', 'error_code', 'error_type', 'reason',
  'breaking', 'breaking_count', 'compatible_count', 'change_count',
  'tool_count', 'hash', 'previous_hash', 'current_hash', 'protocol',
  'timeout_ms', 'max_bytes', 'exit_code', 'signal', 'external_trace_id_present',
]);

function safeText(value, limit = 160) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, 'Bearer [REDACTED]')
    .replace(/([?&](?:token|secret|password|api[_-]?key|authorization)=)[^&\s]+/gi, '$1[REDACTED]')
    .slice(0, limit);
}

function safeRequestId(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'string') return safeText(value, 80);
  if (/^number:-?(?:\d+\.?\d*|\.\d+)$/.test(value)) return value;
  if (/^string:sha256:[a-f0-9]{20}$/i.test(value)) return value;
  return 'string:sha256:' + createHash('sha256').update(value).digest('hex').slice(0, 20);
}

export function isDashboardActive() {
  return activeDashboardServers > 0;
}

export function activateDashboardEventCapture() {
  activeDashboardServers += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    activeDashboardServers = Math.max(0, activeDashboardServers - 1);
  };
}

export function publishDashboardEvent(record) {
  if (!record || typeof record !== 'object') return undefined;
  const event = {
    id: nextId++,
    time: typeof record.time === 'string' ? safeText(record.time, 40) : new Date().toISOString(),
    level: ['debug', 'info', 'warn', 'error'].includes(record.level) ? record.level : 'info',
    event: safeText(record.event || 'inspector.event', 100),
  };
  for (const [key, value] of Object.entries(record)) {
    if (!SAFE_FIELDS.has(key) || value === undefined) continue;
    if (key === 'request_id') {
      event.request_id = safeRequestId(value);
    } else if (typeof value === 'string') {
      event[key] = safeText(value);
    } else if (typeof value === 'number' && Number.isFinite(value)) {
      event[key] = value;
    } else if (typeof value === 'boolean' || value === null) {
      event[key] = value;
    }
  }

  events.push(event);
  totalPublished += 1;
  if (events.length > MAX_EVENTS) events.splice(0, events.length - MAX_EVENTS);
  emitter.emit('event', event);
  return event;
}

export function getDashboardEvents({ limit = 250, afterId = 0 } = {}) {
  const safeLimit = Number.isSafeInteger(limit) ? Math.max(1, Math.min(500, limit)) : 250;
  const safeAfter = Number.isSafeInteger(afterId) ? Math.max(0, afterId) : 0;
  return events.filter((event) => event.id > safeAfter).slice(-safeLimit).map((event) => ({ ...event }));
}

export function getDashboardSummary() {
  const requests = events.filter((event) => event.event === 'rpc.request');
  const responses = events.filter((event) => event.event === 'rpc.response');
  const latencies = responses
    .map((event) => event.duration_ms)
    .filter((value) => typeof value === 'number' && Number.isFinite(value) && value >= 0)
    .sort((a, b) => a - b);
  const percentile = (ratio) => latencies.length
    ? Number(latencies[Math.min(latencies.length - 1, Math.ceil(latencies.length * ratio) - 1)].toFixed(2))
    : null;
  const errors = events.filter((event) =>
    event.is_error === true ||
    (['warn', 'error'].includes(event.level) && /rpc|contract|proxy|http/.test(event.event))).length;
  const breaking = events.filter((event) => event.event === 'contract.diff' && event.breaking === true).length;

  return {
    totalEvents: totalPublished,
    retainedEvents: events.length,
    requests: requests.length,
    responses: responses.length,
    toolCalls: requests.filter((event) => event.method === 'tools/call').length,
    errors,
    breakingChanges: breaking,
    latencyP50Ms: percentile(0.50),
    latencyP95Ms: percentile(0.95),
    latestEventId: events.length ? events[events.length - 1].id : 0,
  };
}

export function onDashboardEvent(listener) {
  emitter.on('event', listener);
  return () => emitter.off('event', listener);
}

export function resetDashboardEventStore() {
  events.length = 0;
  nextId = 1;
  totalPublished = 0;
}
