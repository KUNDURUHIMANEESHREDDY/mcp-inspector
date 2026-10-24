import test from 'node:test';
import assert from 'node:assert/strict';
import { validateJsonRpcEnvelope, summarizeCompatibilityResults } from '../src/compatibility/engine.js';

test('JSON-RPC validator accepts requests, notifications, responses, null IDs, and extension members', () => {
  assert.deepEqual(validateJsonRpcEnvelope({ jsonrpc: '2.0', id: 1, method: 'ping' }), { valid: true, kind: 'request', errors: [] });
  assert.equal(validateJsonRpcEnvelope({ jsonrpc: '2.0', id: null, method: 'ping' }).valid, true);
  assert.equal(validateJsonRpcEnvelope({ jsonrpc: '2.0', method: 'notifications/initialized' }).kind, 'notification');
  assert.deepEqual(validateJsonRpcEnvelope({ jsonrpc: '2.0', id: 'abc', result: { tools: [] }, _meta: { trace_id: 'abc' } }), { valid: true, kind: 'response', errors: [] });
});

test('JSON-RPC validator rejects malformed envelopes and invalid error objects', () => {
  assert.equal(validateJsonRpcEnvelope(null).valid, false);
  assert.ok(validateJsonRpcEnvelope({ jsonrpc: '1.0', id: 1, method: 'ping' }).errors.includes('jsonrpc_must_equal_2.0'));
  assert.ok(validateJsonRpcEnvelope({ jsonrpc: '2.0', id: 1, method: 'ping', result: {} }).errors.includes('request_must_not_include_result_or_error'));
  assert.ok(validateJsonRpcEnvelope({ jsonrpc: '2.0', id: 1, error: { code: 'bad', message: 4 } }).errors.includes('error_code_must_be_integer'));
  assert.ok(validateJsonRpcEnvelope({ jsonrpc: '2.0', id: 1, result: null, error: { code: -1, message: 'x' } }).errors.includes('response_must_include_exactly_one_of_result_or_error'));
  assert.ok(validateJsonRpcEnvelope({ jsonrpc: '2.0', id: true, method: 'ping' }).errors.includes('request_id_must_be_string_number_or_null'));
});

test('compatibility summaries fail closed for failed or cancelled probes', () => {
  assert.deepEqual(summarizeCompatibilityResults([{ status: 'passed' }, { status: 'passed' }]), { passed: 2, failed: 0, cancelled: 0, total: 2, success: true });
  assert.equal(summarizeCompatibilityResults([{ status: 'passed' }, { status: 'failed' }]).success, false);
  assert.equal(summarizeCompatibilityResults([{ status: 'cancelled' }]).success, false);
});
