// Shared credential redaction for logs and dashboard events.
// Keep the token patterns in one place so observability surfaces cannot drift.
const BEARER_CREDENTIAL = /\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi;
const AUTHORIZATION_HEADER = /\b((?:Proxy-)?Authorization\s*:\s*)[^\r\n]+/gi;
const SENSITIVE_HEADER = /\b((?:x-api-key|x-auth-token|api-key|x-amz-security-token|cookie|set-cookie)\s*:\s*)[^\r\n]+/gi;
const URL_USERINFO = /\b(https?:\/\/)[^\s/@]+@/gi;
// OAuth authorization codes/state, signed URLs, JWTs and private-key query
// values are credentials too; redact them before telemetry can retain a URL.
const SENSITIVE_QUERY_PARAMETER_NAME = /^(?:access[_-]?token|refresh[_-]?token|id[_-]?token|authorization[_-]?code|code|state|client[_-]?secret|signature|sig|jwt|assertion|signed[_-]?request|oauth[_-]?token|token|api[_-]?key|secret|private[_-]?key|password|authorization|session(?:[_-]?id)?|cookie)$/i;
// Some URL producers use semicolons as query separators. OAuth implicit-flow
// credentials can also live in URL fragments, so treat '#', '&', and ';' as
// parameter boundaries. This redacts token-like fragment parameters without
// rewriting ordinary fragment identifiers.
const QUERY_PARAMETER = /([?&;#])([^=?&#;\s]+)=([^&#;\s]*)/g;
const KNOWN_TOKEN_FORMAT = /\b(?:sk-[A-Za-z0-9_-]{16,}|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})\b/g;

function normalizeQueryParameterName(name) {
  // Frameworks commonly normalize bracketed query keys such as
  // access_token[] or client_secret[0] to their base credential name.
  // Strip one or more trailing array/index segments before matching.
  return name.replace(/(?:\[[^\]]*\])+$/, '');
}

function isSensitiveQueryParameterName(name) {
  return SENSITIVE_QUERY_PARAMETER_NAME.test(normalizeQueryParameterName(name));
}

function resemblesSensitiveEncodedQueryName(name) {
  // Used only when decoding fails or the bounded decoder is exhausted.
  // Repeated encoding of "%5F" is shaped like "%2525255F", not a repetition
  // of the literal "%25" token. Also treat malformed percent escapes as
  // suspicious when the surrounding key already resembles a credential.
  const nestedEncoding = /%(?:25)+/i.test(name);
  const malformedEncoding = /%(?![0-9a-f]{2})/i.test(name);
  const credentialMarker =
    /(?:^|[^a-z0-9])(?:access|refresh|id|client|api|private|oauth|token|secret|key|code|state|signature|sig|jwt|assertion|password|authorization|cookie|session)(?:$|[^a-z0-9])/i.test(name);
  return (nestedEncoding || malformedEncoding) && credentialMarker;
}

function redactQueryParameters(value) {
  return value.replace(QUERY_PARAMETER, (match, separator, rawName) => {
    // '+' is a space in a query parameter name. Do this once, before decoding,
    // so a decoded literal plus is not repeatedly rewritten.
    let name = rawName.replace(/\+/g, ' ');
    // A URL can be encoded more than once by a proxy or telemetry wrapper.
    // Decode only a bounded number of layers; never allow an unbounded loop on
    // attacker-controlled log input.
    for (let depth = 0; depth < 5; depth += 1) {
      if (isSensitiveQueryParameterName(name)) {
        return `${separator}${rawName}=[REDACTED]`;
      }
      let decoded;
      try {
        decoded = decodeURIComponent(name);
      } catch {
        // If a malformed name resembles a credential, fail closed.
        return resemblesSensitiveEncodedQueryName(name)
          ? `${separator}${rawName}=[REDACTED]`
          : match;
      }
      if (decoded === name) return match;
      name = decoded;
    }
    return isSensitiveQueryParameterName(name) || resemblesSensitiveEncodedQueryName(name)
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
