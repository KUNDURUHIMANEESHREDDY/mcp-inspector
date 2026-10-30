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

import { log } from '../src/observability/logger.js';

test('stderr structured logs redact ID/session/private keys and common credential formats', () => {
  const chunks = [];
  const originalWrite = process.stderr.write;
  process.stderr.write = (chunk, ...args) => {
    chunks.push(String(chunk));
    const callback = args.find((arg) => typeof arg === 'function');
    if (callback) callback();
    return true;
  };
  try {
    log('warn', 'credential.redaction.test', {
      id_token: 'id-token-secret',
      session_id: 'session-id-secret',
      private_key: 'private-key-secret',
      callback: 'https://issuer.example/cb?id_token=query-id-secret&session_id=query-session-secret',
      provider_output: 'sk-proj-1234567890abcdefghijklmnop ghp_abcdefghijklmnopqrstuvwxyz0123456789 AKIAIOSFODNN7EXAMPLE',
    });
  } finally {
    process.stderr.write = originalWrite;
  }
  const output = chunks.join('');
  assert.doesNotMatch(output, /id-token-secret|session-id-secret|private-key-secret|query-id-secret|query-session-secret|sk-proj-1234567890|ghp_abcdefghijklmnopqrstuvwxyz|AKIAIOSFODNN7EXAMPLE/);
  assert.match(output, /"id_token":"\[REDACTED\]"/);
  assert.match(output, /"session_id":"\[REDACTED\]"/);
  assert.match(output, /"private_key":"\[REDACTED\]"/);
  assert.match(output, /id_token=\[REDACTED\]&session_id=\[REDACTED\]/);
});

test('URL userinfo redaction removes malformed raw at-sign suffixes without leaking credentials', async () => {
  const { redactSecrets } = await import('../src/observability/redact-secrets.js');
  const input = 'connect https://alice:p@ss@issuer.example/path?keep=yes';
  const output = redactSecrets(input);
  assert.doesNotMatch(output, /alice|p@ss|ss@issuer/);
  assert.match(output, /https:\/\/\[REDACTED\]@issuer\.example\/path\?keep=yes/);
});

test('URL userinfo redaction covers WHATWG backslash and slashless special-scheme forms', async () => {
  const { redactSecrets } = await import('../src/observability/redact-secrets.js');
  const inputs = [
    'connect https:\\alice:pass@issuer.example/path',
    'connect https:/\\alice:pass@issuer.example/path',
    'connect https:alice:pass@issuer.example/path',
  ];
  for (const input of inputs) {
    const output = redactSecrets(input);
    assert.doesNotMatch(output, /alice|pass/);
    assert.match(output, /issuer\.example\/path/);
  }
});
