// Shared credential redaction for logs and dashboard events.
// Keep the token patterns in one place so observability surfaces cannot drift.
const BEARER_CREDENTIAL = /\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi;
const AUTHORIZATION_HEADER = /\b((?:Proxy-)?Authorization\s*:\s*)[^\r\n]+/gi;
const SENSITIVE_HEADER = /\b((?:x-api-key|x-auth-token|api-key|x-amz-security-token|cookie|set-cookie)\s*:\s*)[^\r\n]+/gi;
const URL_USERINFO = /\b(https?:\/\/)[^\s/@]+@/gi;
// OAuth authorization codes/state, signed URLs, JWTs and private-key query
// values are credentials too; redact them before telemetry can retain a URL.
const SENSITIVE_QUERY_PARAMETER_NAME = /^(?:access[_-]?token|refresh[_-]?token|id[_-]?token|authorization[_-]?code|code|state|client[_-]?secret|signature|sig|jwt|assertion|signed[_-]?request|oauth[_-]?token|token|api[_-]?key|secret|private[_-]?key|password|authorization|session(?:[_-]?id)?|cookie)$/i;
// Some URL producers use semicolons as query separators. Treat them like '&'
// so a later credential parameter cannot hide inside the preceding value.
const QUERY_PARAMETER = /([?&;])([^=&#;\s]+)=([^&#;\s]*)/g;
const KNOWN_TOKEN_FORMAT = /\b(?:sk-[A-Za-z0-9_-]{16,}|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})\b/g;

function redactQueryParameters(value) {
  return value.replace(QUERY_PARAMETER, (match, separator, rawName) => {
    let name = rawName;
    try {
      // Raw telemetry URLs can percent-encode parameter names as well as values.
      name = decodeURIComponent(rawName.replace(/\+/g, ' '));
    } catch {
      // If a malformed name resembles a sensitive key, fail closed rather than
      // retaining a potentially credential-bearing value.
      if (/(?:access|refresh|id|client|api|private|oauth)[_-]?%?(?:5f|2d)?[_-]?(?:token|secret|key)|^(?:code|state|signature|sig|jwt|assertion|password|authorization|cookie|session)/i.test(rawName)) {
        return `${separator}${rawName}=[REDACTED]`;
      }
      return match;
    }
    return SENSITIVE_QUERY_PARAMETER_NAME.test(name)
      ? `${separator}${rawName}=[REDACTED]`
      : match;
  });
}

export function redactSecrets(value) {
  const text = String(value ?? '')
    .replace(URL_USERINFO, '$1[REDACTED]@')
    .replace(AUTHORIZATION_HEADER, '$1[REDACTED]')
    .replace(SENSITIVE_HEADER, '$1[REDACTED]')
    .replace(BEARER_CREDENTIAL, 'Bearer [REDACTED]');
  return redactQueryParameters(text).replace(KNOWN_TOKEN_FORMAT, '[REDACTED]');
}
