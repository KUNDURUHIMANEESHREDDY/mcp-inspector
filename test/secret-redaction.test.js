import test from 'node:test';
import assert from 'node:assert/strict';
import { redactSecrets } from '../src/observability/redact-secrets.js';

test('shared redaction covers supported credential formats and URL parameters', () => {
  // Assemble synthetic values at runtime so repository secret scanning does not
  // mistake test fixtures for credentials.
  const tokens = [
    ['github_pat_', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL'].join(''),
    ['ghp_', 'abcdefghijklmnopqrstuvwxyz0123456789'].join(''),
    ['gho_', 'abcdefghijklmnopqrstuvwxyz0123456789'].join(''),
    ['ghu_', 'abcdefghijklmnopqrstuvwxyz0123456789'].join(''),
    ['ghs_', 'abcdefghijklmnopqrstuvwxyz0123456789'].join(''),
    ['ghr_', 'abcdefghijklmnopqrstuvwxyz0123456789'].join(''),
    ['sk-proj-', '1234567890abcdefghijklmnop'].join(''),
    ['AKIA', 'IOSFODNN7EXAMPLE'].join(''),
    ['xox', 'b-', '1234567890', '-', 'abcdefghijklmnopqrstuvwxyz'].join(''),
    ['AIza', 'SyD1234567890abcdefghijklmnopqrstuv'].join(''),
  ];
  const input = [
    ['Bearer ', 'bearer-example-secret'].join(''),
    ['https://example.test/?access_token=', 'query-access-secret', '&refresh_token=', 'query-refresh-secret'].join(''),
    ...tokens,
  ].join(' ');
  const safe = redactSecrets(input);

  assert.doesNotMatch(safe, /bearer-example-secret|query-access-secret|query-refresh-secret/);
  for (const token of tokens) assert.ok(!safe.includes(token), 'token was not redacted');
  assert.match(safe, /Bearer \[REDACTED\]/);
  assert.match(safe, /access_token=\[REDACTED\]/);
  assert.match(safe, /refresh_token=\[REDACTED\]/);
  assert.equal((safe.match(/\[REDACTED\]/g) || []).length, tokens.length + 3);
});

test('shared redaction preserves ordinary diagnostic text', () => {
  assert.equal(redactSecrets('rpc.request method=tools/call'), 'rpc.request method=tools/call');
});

test('shared redaction removes Basic credentials, sensitive headers, and URL userinfo', () => {
  const input = [
    ['Authorization: Basic ', 'dXNlcjpwYXNz'].join(''),
    ['Proxy-Authorization: Basic ', 'cHJveHk6cGFzcw=='].join(''),
    ['Authorization: Token ', 'token-scheme-secret'].join(''),
    ['Proxy-Authorization: Digest ', 'digest-scheme-secret'].join(''),
    ['X-API-Key: ', 'header-api-key-secret'].join(''),
    ['Cookie: session=', 'cookie-session-secret'].join(''),
    ['https://', 'user:password', '@example.test/path'].join(''),
  ].join('\n');
  const safe = redactSecrets(input);

  assert.doesNotMatch(safe, /dXNlcjpwYXNz|cHJveHk6cGFzcw==|token-scheme-secret|digest-scheme-secret|header-api-key-secret|cookie-session-secret|user:password/);
  assert.match(safe, /Authorization: \[REDACTED\]/);
  assert.match(safe, /Proxy-Authorization: \[REDACTED\]/);
  assert.match(safe, /X-API-Key: \[REDACTED\]/);
  assert.match(safe, /Cookie: \[REDACTED\]/);
  assert.match(safe, /https:\/\/\[REDACTED\]@example\.test\/path/);
});

test('shared redaction removes OAuth codes, state, signatures, and JWT query values', () => {
  const input = [
    ['https://idp.example/callback?code=', 'oauth-code-secret'],
    ['&state=', 'csrf-state-secret'],
    ['&signature=', 'signed-url-secret'],
    ['&jwt=', 'jwt-query-secret'],
    ['&private_key=', 'private-key-secret'],
  ].join('');
  const safe = redactSecrets(input);

  assert.doesNotMatch(
    safe,
    /oauth-code-secret|csrf-state-secret|signed-url-secret|jwt-query-secret|private-key-secret/,
  );
  assert.match(safe, /code=\[REDACTED\]/);
  assert.match(safe, /state=\[REDACTED\]/);
  assert.match(safe, /signature=\[REDACTED\]/);
  assert.match(safe, /jwt=\[REDACTED\]/);
  assert.match(safe, /private_key=\[REDACTED\]/);
});

test('redacts percent-encoded sensitive query names without changing safe parameters', () => {
  const input = [
    ['https://example.test/callback?access%5Ftoken=', 'encoded-access-secret'].join(''),
    ['&client%2Dsecret=', 'encoded-client-secret'].join(''),
    ['&safe%5Fparameter=', 'keep-this-value'].join(''),
    ['&access%5Ftoken%ZZ=', 'malformed-encoded-secret'].join(''),
  ].join('');
  const safe = redactSecrets(input);

  assert.doesNotMatch(safe, /encoded-access-secret|encoded-client-secret|malformed-encoded-secret/);
  assert.match(safe, /access%5Ftoken=\[REDACTED\]/);
  assert.match(safe, /client%2Dsecret=\[REDACTED\]/);
  assert.match(safe, /safe%5Fparameter=keep-this-value/);
  assert.match(safe, /access%5Ftoken%ZZ=\[REDACTED\]/);
});

test('redacts semicolon-delimited credentials while preserving safe query values', () => {
  const input = [
    'https://example.test/callback?safe=keep-this-value;access_token=semicolon-access-secret;client%2Dsecret=semicolon-client-secret',
  ].join('');
  const safe = redactSecrets(input);

  assert.doesNotMatch(safe, /semicolon-access-secret|semicolon-client-secret/);
  assert.match(safe, /safe=keep-this-value/);
  assert.match(safe, /;access_token=\[REDACTED\]/);
  assert.match(safe, /;client%2Dsecret=\[REDACTED\]/);
});

test('redacts bracketed credential query keys while preserving safe arrays', () => {
  const input = [
    'https://example.test/callback?access_token[]=array-access-secret',
    '&client%5Fsecret%5B0%5D=array-client-secret',
    '&refresh_token[primary][value]=nested-refresh-secret',
    '&safe[0]=keep-this-value',
  ].join('');
  const safe = redactSecrets(input);

  assert.doesNotMatch(safe, /array-access-secret|array-client-secret|nested-refresh-secret/);
  assert.match(safe, /access_token\[\]=\[REDACTED\]/);
  assert.match(safe, /client%5Fsecret%5B0%5D=\[REDACTED\]/);
  assert.match(safe, /refresh_token\[primary\]\[value\]=\[REDACTED\]/);
  assert.match(safe, /safe\[0\]=keep-this-value/);
});


test('redacts multiply percent-encoded credential query names without changing safe names', () => {
  const input = [
    'https://example.test/callback?access%255Ftoken=double-encoded-access-secret',
    '&client%252Dsecret=double-encoded-client-secret',
    '&refresh%25255Ftoken=triple-encoded-refresh-secret',
    '&access%2525255Ftoken=quadruple-encoded-access-secret',
    '&access%255Ftoken%ZZ=malformed-double-encoded-secret',
    '&safe%255Fparameter=keep-this-value',
    '&stateful=keep-stateful-value',
  ].join('');
  const safe = redactSecrets(input);

  assert.doesNotMatch(
    safe,
    /double-encoded-access-secret|double-encoded-client-secret|triple-encoded-refresh-secret|quadruple-encoded-access-secret|malformed-double-encoded-secret/,
  );
  assert.match(safe, /access%255Ftoken=\[REDACTED\]/);
  assert.match(safe, /client%252Dsecret=\[REDACTED\]/);
  assert.match(safe, /refresh%25255Ftoken=\[REDACTED\]/);
  assert.match(safe, /access%2525255Ftoken=\[REDACTED\]/);
  assert.match(safe, /access%255Ftoken%ZZ=\[REDACTED\]/);
  assert.match(safe, /safe%255Fparameter=keep-this-value/);
  assert.match(safe, /stateful=keep-stateful-value/);
});

test('redacts OAuth credentials in URL fragments while preserving ordinary anchors', () => {
  const input = [
    'https://idp.example/callback#access_token=fragment-access-secret&refresh_token=fragment-refresh-secret;client_secret=fragment-client-secret',
    'https://idp.example/callback#access%255Ftoken=double-encoded-fragment-secret',
    'https://app.example/#/callback?state=fragment-state-secret&safe=keep-this-value',
    'https://example.test/page#section=shows',
  ].join(' ');
  const safe = redactSecrets(input);

  assert.doesNotMatch(
    safe,
    /fragment-access-secret|fragment-refresh-secret|fragment-client-secret|fragment-state-secret|double-encoded-fragment-secret/,
  );
  assert.ok(safe.includes('#access_token=[REDACTED]'));
  assert.ok(safe.includes('#access%255Ftoken=[REDACTED]'));
  assert.ok(safe.includes('&refresh_token=[REDACTED]'));
  assert.ok(safe.includes(';client_secret=[REDACTED]'));
  assert.ok(safe.includes('#/callback?state=[REDACTED]&safe=keep-this-value'));
  assert.ok(safe.includes('#section=shows'));
});
