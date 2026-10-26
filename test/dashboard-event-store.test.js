import test from 'node:test';
import assert from 'node:assert/strict';
import { getDashboardEvents, getDashboardSummary, publishDashboardEvent, resetDashboardEventStore } from '../src/dashboard/event-store.js';

test('dashboard event store exposes only allowlisted operational metadata', () => {
  resetDashboardEventStore();
  publishDashboardEvent({
    time: '2026-10-24T10:00:00.000Z',
    level: 'info',
    event: 'rpc.request',
    method: 'tools/call',
    tool: 'echo',
    request_id: 'sensitive-customer-id',
    arguments: { prompt: 'do not show' },
    tool_result: { secret: 'do not show' },
    authorization: 'Bearer very-secret',
  });
  const items = getDashboardEvents({ limit: 10 });
  assert.equal(items.length, 1);
  assert.equal(items[0].method, 'tools/call');
  assert.match(items[0].request_id, /^string:sha256:[a-f0-9]{20}$/);
  assert.equal(Object.hasOwn(items[0], 'arguments'), false);
  assert.equal(Object.hasOwn(items[0], 'tool_result'), false);
  assert.equal(Object.hasOwn(items[0], 'authorization'), false);
});

test('dashboard event text redacts token query parameters and common API key formats', () => {
  resetDashboardEventStore();
  publishDashboardEvent({
    event: 'rpc.failure',
    level: 'warn',
    reason: 'request failed?access_token=access-secret&refresh_token=refresh-secret',
    error_type: 'keys sk-proj-1234567890abcdefghijklmnop ghp_abcdefghijklmnopqrstuvwxyz0123456789 github_pat_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL AKIAIOSFODNN7EXAMPLE',
  });
  const [item] = getDashboardEvents({ limit: 10 });
  assert.doesNotMatch(item.reason, /access-secret|refresh-secret/);
  assert.match(item.reason, /access_token=\[REDACTED\]/);
  assert.match(item.reason, /refresh_token=\[REDACTED\]/);
  assert.doesNotMatch(item.error_type, /sk-proj-|ghp_|github_pat_|AKIAIOSFODNN7EXAMPLE/);
  assert.equal((item.error_type.match(/\[REDACTED\]/g) || []).length, 4);
});

test('dashboard summary calculates counts and latency percentiles', () => {
  resetDashboardEventStore();
  publishDashboardEvent({ event: 'rpc.request', level: 'info', method: 'tools/call' });
  publishDashboardEvent({ event: 'rpc.response', level: 'info', method: 'tools/call', duration_ms: 10, is_error: false });
  publishDashboardEvent({ event: 'rpc.response', level: 'warn', method: 'tools/call', duration_ms: 30, is_error: true });
  publishDashboardEvent({ event: 'contract.diff', level: 'warn', breaking: true });
  const summary = getDashboardSummary();
  assert.equal(summary.requests, 1);
  assert.equal(summary.responses, 2);
  assert.equal(summary.toolCalls, 1);
  assert.equal(summary.errors, 2);
  assert.equal(summary.breakingChanges, 1);
  assert.equal(summary.latencyP50Ms, 10);
  assert.equal(summary.latencyP95Ms, 30);
  assert.equal(summary.latencyP99Ms, 30);
  assert.equal(summary.errorRatePercent, 50);
  assert.equal(summary.schemaDriftEvents, 1);
});

test('dashboard event store caps retained history and query limits', () => {
  resetDashboardEventStore();
  for (let index = 0; index < 2200; index += 1) publishDashboardEvent({ event: 'rpc.request', level: 'info', method: 'ping' });
  const latest = getDashboardEvents({ limit: 500 });
  assert.equal(latest.length, 500);
  assert.equal(latest[0].id, 1701);
  assert.equal(latest[499].id, 2200);
  assert.equal(getDashboardEvents({ limit: 500, afterId: 2198 }).length, 2);
  assert.equal(getDashboardSummary().retainedEvents, 2000);
  assert.equal(getDashboardSummary().totalEvents, 2200);
});

test('dashboard summary reports bounded-window throughput, timeouts, and repeated failures', () => {
  resetDashboardEventStore();
  const now = Date.now();
  const time = new Date(now).toISOString();
  for (let index = 0; index < 3; index += 1) {
    publishDashboardEvent({ time, event: 'rpc.response', level: 'warn', method: 'tools/call', tool: 'echo', is_error: true, error_code: -1, duration_ms: 12 });
  }
  publishDashboardEvent({ time, event: 'rpc.request', level: 'info', method: 'tools/call' });
  publishDashboardEvent({ time, event: 'rpc.timeout', level: 'warn', reason: 'timeout' });
  const summary = getDashboardSummary({ now });
  assert.equal(summary.timeouts, 1);
  assert.equal(summary.errorRatePercent, 100);
  assert.equal(summary.repeatedFailureGroups, 1);
  assert.equal(summary.throughputRequestsPerSecond, 0.017);
  assert.equal(summary.latencyP99Ms, 12);
});
