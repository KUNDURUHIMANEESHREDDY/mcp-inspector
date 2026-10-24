import test from 'node:test';
import assert from 'node:assert/strict';
import { getDashboardEvents, resetDashboardEventStore, publishDashboardEvent } from '../src/dashboard/event-store.js';

test('untrusted event metadata is allowlisted, bounded, and secret-redacted', () => {
  resetDashboardEventStore();
  publishDashboardEvent({
    event: 'rpc.response?token=top-secret',
    level: 'warn',
    method: 'tools/call?api_key=private-value',
    tool: 'tool Bearer private-bearer',
    request_id: 'private-user-identifier',
    arguments: { password: 'private-password' },
    response_body: { access_token: 'private-token' },
    authorization: 'Bearer private-bearer',
  });
  const [event] = getDashboardEvents({ limit: 1 });
  const serialized = JSON.stringify(event);
  assert.doesNotMatch(serialized, /top-secret|private-value|private-bearer|private-password|private-token|private-user-identifier/);
  assert.equal(Object.hasOwn(event, 'arguments'), false);
  assert.equal(Object.hasOwn(event, 'response_body'), false);
  assert.equal(Object.hasOwn(event, 'authorization'), false);
  assert.ok(event.event.length <= 100);
  assert.ok(event.tool.length <= 160);
});

test('dashboard retention is bounded and event IDs remain monotonic after trimming', () => {
  resetDashboardEventStore();
  for (let index = 0; index < 2050; index += 1) publishDashboardEvent({ event: 'rpc.request', method: 'ping' });
  const current = getDashboardEvents({ limit: 500 });
  assert.equal(current.length, 500);
  assert.equal(current[0].id, 1551);
  assert.equal(current[499].id, 2050);
});
