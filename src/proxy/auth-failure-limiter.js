// Per-peer failed-authentication throttling for the remote HTTP proxy.
// Keep this state bounded: peer addresses are attacker-influenced at the network edge.
export function createAuthFailureLimiter({ maxAttempts = 10, windowMs = 60_000, maxEntries = 4096 } = {}) {
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) throw new RangeError('maxAttempts must be a positive safe integer');
  if (!Number.isSafeInteger(windowMs) || windowMs < 1) throw new RangeError('windowMs must be a positive safe integer');
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) throw new RangeError('maxEntries must be a positive safe integer');

  const attempts = new Map();
  const keyFor = (address) => typeof address === 'string' && address ? address : 'unknown';
  return {
    recordFailure(address) {
      const key = keyFor(address);
      const now = Date.now();
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
