// Shared credential redaction for logs and dashboard events.
// Keep the token patterns in one place so observability surfaces cannot drift.
const BEARER_CREDENTIAL = /\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi;
const SENSITIVE_QUERY_PARAMETER = /([?&](?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|token|api[_-]?key|secret|password|authorization|session(?:[_-]?id)?|cookie)=)[^&#\s]+/gi;
const KNOWN_TOKEN_FORMAT = /\b(?:sk-[A-Za-z0-9_-]{16,}|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})\b/g;

export function redactSecrets(value) {
  return String(value ?? '')
    .replace(BEARER_CREDENTIAL, 'Bearer [REDACTED]')
    .replace(SENSITIVE_QUERY_PARAMETER, '$1[REDACTED]')
    .replace(KNOWN_TOKEN_FORMAT, '[REDACTED]');
}
