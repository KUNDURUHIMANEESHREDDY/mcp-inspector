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
  for (const token of tokens) assert.ok(!safe.includes(token), `token was not redacted: ${token.slice(0, 8)}`);
  assert.match(safe, /Bearer \[REDACTED\]/);
  assert.match(safe, /access_token=\[REDACTED\]/);
  assert.match(safe, /refresh_token=\[REDACTED\]/);
  assert.equal((safe.match(/\[REDACTED\]/g) || []).length, tokens.length + 3);
});

test('shared redaction preserves ordinary diagnostic text', () => {
  assert.equal(redactSecrets('rpc.request method=tools/call'), 'rpc.request method=tools/call');
});
