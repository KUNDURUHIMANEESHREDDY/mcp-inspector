import { performance } from 'node:perf_hooks';

// Per-peer failed-authentication throttling for the remote HTTP proxy.
// Keep this state bounded: peer addresses are attacker-influenced at the network edge.
// Use a monotonic clock so wall-clock corrections cannot extend or bypass a failure window.
export function createAuthFailureLimiter({
  maxAttempts = 10,
  windowMs = 60_000,
  maxEntries = 4096,
  clock = () => performance.now(),
} = {}) {
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) throw new RangeError('maxAttempts must be a positive safe integer');
  if (!Number.isSafeInteger(windowMs) || windowMs < 1) throw new RangeError('windowMs must be a positive safe integer');
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) throw new RangeError('maxEntries must be a positive safe integer');
  if (typeof clock !== 'function') throw new TypeError('clock must be a function');

  const attempts = new Map();
  const keyFor = (address) => typeof address === 'string' && address ? address : 'unknown';
  return {
    recordFailure(address) {
      const key = keyFor(address);
      const now = clock();
      if (!Number.isFinite(now)) throw new RangeError('clock must return a finite number');
      let entry = attempts.get(key);
      if (!entry || now - entry.startedAt >= windowMs) entry = { startedAt: now, count: 0 };
      entry.count += 1;
      // Map insertion order acts as an LRU queue. Refresh the current peer before
      // evicting so a noisy new peer cannot displace every active peer at once.
      attempts.delete(key);
      attempts.set(key, entry);
      while (attempts.size > maxEntries) attempts.delete(attempts.keys().next().value);
      if (entry.count <= maxAttempts) return 0;
      return Math.max(1, Math.ceil((windowMs - (now - entry.startedAt)) / 1000));
    },
    clear(address) {
      attempts.delete(keyFor(address));
    },
  };
}
