// Shared credential redaction for logs and dashboard events.
// Keep the token patterns in one place so observability surfaces cannot drift.
const BEARER_CREDENTIAL = /\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi;
const AUTHORIZATION_HEADER = /\b((?:Proxy-)?Authorization\s*:\s*)[^\r\n]+/gi;
const SENSITIVE_HEADER = /\b((?:x-api-key|x-auth-token|api-key|x-amz-security-token|cookie|set-cookie)\s*:\s*)[^\r\n]+/gi;
const URL_USERINFO = /\b(https?:\/\/)[^\s/@]+@/gi;
// OAuth authorization codes/state, signed URLs, JWTs and private-key query
// values are credentials too; redact them before telemetry can retain a URL.
const SENSITIVE_QUERY_PARAMETER = /([?&](?:access[_-]?token|refresh[_-]?token|id[_-]?token|authorization[_-]?code|code|state|client[_-]?secret|signature|sig|jwt|assertion|signed[_-]?request|oauth[_-]?token|token|api[_-]?key|secret|private[_-]?key|password|authorization|session(?:[_-]?id)?|cookie)=)[^&#\s]+/gi;
const KNOWN_TOKEN_FORMAT = /\b(?:sk-[A-Za-z0-9_-]{16,}|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})\b/g;

export function redactSecrets(value) {
  return String(value ?? '')
    .replace(URL_USERINFO, '$1[REDACTED]@')
    .replace(AUTHORIZATION_HEADER, '$1[REDACTED]')
    .replace(SENSITIVE_HEADER, '$1[REDACTED]')
    .replace(BEARER_CREDENTIAL, 'Bearer [REDACTED]')
    .replace(SENSITIVE_QUERY_PARAMETER, '$1[REDACTED]')
    .replace(KNOWN_TOKEN_FORMAT, '[REDACTED]');
}
