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
    ['Authorization: Bearer ', 'bearer-example-secret'].join(''),
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
    ['X-API-Key: ', 'header-api-key-secret'].join(''),
    ['Cookie: session=', 'cookie-session-secret'].join(''),
    ['https://', 'user:password', '@example.test/path'].join(''),
  ].join('\n');
  const safe = redactSecrets(input);

  assert.doesNotMatch(safe, /dXNlcjpwYXNz|cHJveHk6cGFzcw==|header-api-key-secret|cookie-session-secret|user:password/);
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
