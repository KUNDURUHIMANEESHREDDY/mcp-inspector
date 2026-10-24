import { createHash } from 'node:crypto';

const LEVELS = Object.freeze({ debug: 10, info: 20, warn: 30, error: 40 });
const configuredLevel = process.env.MCP_INSPECTOR_LOG_LEVEL ?? 'info';
const threshold = LEVELS[configuredLevel] ?? LEVELS.info;
const SENSITIVE_KEY = /(authorization|access[_-]?token|refresh[_-]?token|api[_-]?key|password|secret|cookie|prompt|arguments|tool[_-]?result)/i;

export function safeString(value) {
  return String(value ?? '')
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, 'Bearer [REDACTED]')
    .replace(/([?&](?:access[_-]?token|refresh[_-]?token|client[_-]?secret|token|api[_-]?key|secret|password|authorization|cookie)=)[^&\s]+/gi, '$1[REDACTED]')
    .slice(0, 240);
}

function sanitizeValue(key, value, depth = 0) {
  if (SENSITIVE_KEY.test(key)) return '[REDACTED]';
  if (typeof value === 'string') return safeString(value);
  if (value === null || ['number', 'boolean'].includes(typeof value)) return value;
  if (Array.isArray(value)) {
    return value.slice(0, 100).map((item) => sanitizeValue(key, item, depth + 1));
  }
  if (value && typeof value === 'object') {
    if (depth >= 3) return '[object]';
    const safe = {};
    for (const [childKey, childValue] of Object.entries(value).slice(0, 50)) {
      safe[childKey] = sanitizeValue(childKey, childValue, depth + 1);
    }
    return safe;
  }
  return value === undefined ? undefined : safeString(value);
}

export function log(level, event, fields = {}) {
  if (!(level in LEVELS) || LEVELS[level] < threshold) return;
  const safeFields = {};
  for (const [key, value] of Object.entries(fields)) safeFields[key] = sanitizeValue(key, value);
  const record = { time: new Date().toISOString(), level, event: safeString(event), ...safeFields };
  // The protocol channel is stdout for stdio MCP servers. Diagnostics must never
  // contaminate it, so every log record is written to stderr only.
  try {
    process.stderr.write(`${JSON.stringify(record)}\n`);
  } catch {
    // A broken diagnostics pipe must not break the protocol forwarding path.
  }
}

export function errorKind(error) {
  if (!error || typeof error !== 'object') return 'Error';
  return safeString(error.name || error.code || 'Error');
}

export function requestKey(id) {
  if (typeof id === 'number') return `number:${id}`;
  // String request IDs are attacker-controlled metadata. Keep correlation exact
  // without copying potentially sensitive or enormous values into logs/spans.
  if (typeof id === 'string') {
    const digest = createHash('sha256').update(id).digest('hex').slice(0, 20);
    return `string:sha256:${digest}`;
  }
  return `${typeof id}:${String(id).slice(0, 64)}`;
}

export function logError(event, error, fields = {}) {
  log('error', event, { ...fields, error_type: errorKind(error) });
}
