import test from 'node:test';
import assert from 'node:assert/strict';
import { requestKey, safeString } from '../src/observability/logger.js';

test('string JSON-RPC ids are correlated without logging the raw identifier', () => {
  const id = 'sensitive-user-supplied-id';
  const key = requestKey(id);
  assert.match(key, /^string:sha256:[a-f0-9]{20}$/);
  assert.ok(!key.includes(id));
  assert.equal(requestKey(id), key);
  assert.notEqual(requestKey('another-id'), key);
});

test('log string sanitization redacts bearer credentials and URL secrets', () => {
  const safe = safeString('Authorization: Bearer abc123 and https://example.test/?access_token=secret');
  assert.ok(!safe.includes('abc123'));
  assert.ok(!safe.includes('secret'));
  assert.match(safe, /REDACTED/);
});
