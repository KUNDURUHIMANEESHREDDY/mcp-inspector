import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuthFailureLimiter } from '../src/proxy/auth-failure-limiter.js';

test('failed-auth state is bounded and evicts the least-recently-used peer', () => {
  const limiter = createAuthFailureLimiter({ maxAttempts: 2, windowMs: 60_000, maxEntries: 2 });

  assert.equal(limiter.recordFailure('peer-a'), 0);
  assert.equal(limiter.recordFailure('peer-b'), 0);
  assert.equal(limiter.recordFailure('peer-a'), 0); // Refresh peer-a in the LRU order.
  assert.equal(limiter.recordFailure('peer-c'), 0); // Evicts peer-b, the least-recently-used peer.
  assert.ok(limiter.recordFailure('peer-a') > 0); // Peer-a's failure window was retained.

  assert.equal(limiter.recordFailure('peer-b'), 0); // Evicted peers start a new window.
  assert.equal(limiter.recordFailure('peer-b'), 0);
  assert.ok(limiter.recordFailure('peer-b') > 0);
  limiter.clear('peer-b');
  assert.equal(limiter.recordFailure('peer-b'), 0);
});

test('failed-auth limiter rejects unsafe bounds', () => {
  assert.throws(() => createAuthFailureLimiter({ maxAttempts: 0 }), /maxAttempts/);
  assert.throws(() => createAuthFailureLimiter({ windowMs: 0 }), /windowMs/);
  assert.throws(() => createAuthFailureLimiter({ maxEntries: 0 }), /maxEntries/);
});
