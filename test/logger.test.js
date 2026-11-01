import test from 'node:test';
import assert from 'node:assert/strict';
import { log, requestKey, safeString } from '../src/observability/logger.js';

test('string JSON-RPC ids are correlated without logging the raw identifier', () => {
  const id = 'sensitive-user-supplied-id';
  const key = requestKey(id);
  assert.match(key, /^string:sha256:[a-f0-9]{20}$/);
  assert.ok(!key.includes(id));
  assert.equal(requestKey(id), key);
  assert.notEqual(requestKey('another-id'), key);
});

test('log string sanitization redacts bearer credentials and URL secrets', () => {
  const safe = safeString('Authorization: Bearer abc123 and https://example.test/?access_token=secret github_pat_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL');
  assert.ok(!safe.includes('abc123'));
  assert.ok(!safe.includes('secret'));
  assert.ok(!safe.includes('github_pat_'));
  assert.match(safe, /REDACTED/);
});

test('log sanitization bounds deeply nested arrays without throwing', () => {
  let nested = 'safe diagnostic';
  for (let depth = 0; depth < 10_000; depth += 1) nested = [nested];

  const output = [];
  const originalWrite = process.stderr.write;
  process.stderr.write = (chunk) => {
    output.push(String(chunk));
    return true;
  };

  try {
    assert.doesNotThrow(() => log('info', 'deep-array', { payload: nested }));
  } finally {
    process.stderr.write = originalWrite;
  }

  assert.equal(output.length, 1);
  const record = JSON.parse(output[0]);
  assert.deepEqual(record.payload, [[['[array]']]]);
});
