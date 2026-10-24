import test from 'node:test';
import assert from 'node:assert/strict';
import { isSafeExternalTraceId, isValidTraceparent } from '../src/observability/telemetry.js';

test('traceparent accepts canonical W3C version 00 identifiers', () => {
  assert.equal(isValidTraceparent('00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'), true);
  assert.equal(isValidTraceparent('00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00'), true);
});

test('traceparent rejects zero identifiers, unsupported versions, and malformed values', () => {
  for (const value of [
    '00-00000000000000000000000000000000-00f067aa0ba902b7-01',
    '00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01',
    '01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    'ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra',
    '', null, 123,
  ]) assert.equal(isValidTraceparent(value), false, String(value));
});

test('external trace metadata accepts bounded hex identifiers and rejects arbitrary user strings', () => {
  assert.equal(isSafeExternalTraceId('4bf92f3577b34da6a3ce929d0e0e4736'), true);
  assert.equal(isSafeExternalTraceId('4bf92f35-77b3-4da6-a3ce-929d0e0e4736'), true);
  assert.equal(isSafeExternalTraceId('00000000000000000000000000000000'), false);
  assert.equal(isSafeExternalTraceId('Bearer top-secret-value'), false);
  assert.equal(isSafeExternalTraceId('prompt text from the user'), false);
});
