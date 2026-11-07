import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuthFailureLimiter } from '../src/proxy/auth-failure-limiter.js';

test('failed authentication is throttled per peer and resets after the window', () => {
  let now = 0;
  const limiter = createAuthFailureLimiter({ maxAttempts: 2, windowMs: 1000, clock: () => now });
  assert.equal(limiter.recordFailure('peer-a'), 0);
  assert.equal(limiter.recordFailure('peer-a'), 0);
  assert.equal(limiter.recordFailure('peer-a'), 1);
  now = 1000;
  assert.equal(limiter.recordFailure('peer-a'), 0);
});

test('peers have independent failure windows', () => {
  const limiter = createAuthFailureLimiter({ maxAttempts: 1, windowMs: 1000, clock: () => 10 });
  assert.equal(limiter.recordFailure('peer-a'), 0);
  assert.equal(limiter.recordFailure('peer-a'), 1);
  assert.equal(limiter.recordFailure('peer-b'), 0);
});

test('successful authentication can clear one peer window', () => {
  const limiter = createAuthFailureLimiter({ maxAttempts: 1, windowMs: 1000, clock: () => 10 });
  limiter.recordFailure('peer-a');
  assert.equal(limiter.recordFailure('peer-a'), 1);
  limiter.clear('peer-a');
  assert.equal(limiter.recordFailure('peer-a'), 0);
});

test('the peer map stays bounded and evicts the least recently used key', () => {
  const limiter = createAuthFailureLimiter({ maxAttempts: 1, windowMs: 1000, maxEntries: 2, clock: () => 10 });
  limiter.recordFailure('peer-a');
  limiter.recordFailure('peer-b');
  limiter.recordFailure('peer-c');
  assert.equal(limiter.recordFailure('peer-a'), 0);
});

test('invalid limiter configuration and non-finite clocks fail closed', () => {
  assert.throws(() => createAuthFailureLimiter({ maxAttempts: 0 }), /maxAttempts/);
  assert.throws(() => createAuthFailureLimiter({ windowMs: 0 }), /windowMs/);
  assert.throws(() => createAuthFailureLimiter({ maxEntries: 0 }), /maxEntries/);
  const limiter = createAuthFailureLimiter({ clock: () => Number.NaN });
  assert.throws(() => limiter.recordFailure('peer-a'), /finite number/);
});
