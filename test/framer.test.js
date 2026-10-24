import test from 'node:test';
import assert from 'node:assert/strict';
import { LineFramer, decodeJsonRpcFrame, isJsonRpcMessage } from '../src/protocol/framer.js';

test('LineFramer preserves separate frames across arbitrary chunk boundaries', () => {
  const seen = [];
  const framer = new LineFramer({ onFrame: (frame) => seen.push(frame.toString('utf8')) });
  framer.push(Buffer.from('{"jsonrpc":"2.0","id":1,'));
  framer.push(Buffer.from('"result":{"ok":true}}\r\n{"jsonrpc":"2.0","method":"ping"}\n'));
  framer.end();
  assert.deepEqual(seen, [
    '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\r',
    '{"jsonrpc":"2.0","method":"ping"}',
  ]);
  const first = decodeJsonRpcFrame(Buffer.from(seen[0]));
  assert.equal(first.ok, true);
  assert.equal(isJsonRpcMessage(first.value), true);
  assert.equal(isJsonRpcMessage(JSON.parse(seen[1])), true);
});

test('LineFramer drops oversized frames and resynchronizes at the next newline', () => {
  const seen = [];
  const oversize = [];
  const framer = new LineFramer({
    maxFrameBytes: 1024,
    onFrame: (frame) => seen.push(frame.toString('utf8')),
    onOversize: (details) => oversize.push(details),
  });
  framer.push(Buffer.concat([Buffer.alloc(1050, 0x61), Buffer.from('\n{"jsonrpc":"2.0","method":"ping"}\n')]));
  assert.equal(oversize.length, 1);
  assert.equal(seen.length, 1);
  assert.equal(JSON.parse(seen[0]).method, 'ping');
});

test('JSON-RPC parser rejects malformed JSON and invalid envelope shapes', () => {
  assert.deepEqual(decodeJsonRpcFrame(Buffer.from('{oops')), { ok: false, reason: 'invalid_json' });
  assert.deepEqual(decodeJsonRpcFrame(Buffer.from('  ')), { ok: false, reason: 'empty' });
  assert.equal(isJsonRpcMessage({ jsonrpc: '1.0', id: 1, result: {} }), false);
  assert.equal(isJsonRpcMessage({ jsonrpc: '2.0', id: null, result: {} }), false);
  assert.equal(isJsonRpcMessage({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }), true, 'JSON-RPC permits null IDs on error responses when the request ID is unknown');
  assert.equal(isJsonRpcMessage({ jsonrpc: '2.0', id: null, error: { code: -32700 } }), false, 'error responses still require a valid error object');
  assert.equal(isJsonRpcMessage({ jsonrpc: '2.0', id: null, method: 'tools/call' }), false, 'null is not a valid request ID');
  assert.equal(isJsonRpcMessage([{ jsonrpc: '2.0', id: 1, result: {} }]), false, 'MCP does not accept JSON-RPC batch arrays');
  assert.equal(isJsonRpcMessage({ jsonrpc: '2.0', id: 1, method: 'ping', result: {} }), false, 'requests cannot also contain a result');
  assert.equal(isJsonRpcMessage({ jsonrpc: '2.0', id: 1, method: 'ping', params: 'not-an-object' }), false);
  assert.equal(isJsonRpcMessage({ jsonrpc: '2.0', id: 1, error: { code: 'bad', message: 'error' } }), false);
  assert.equal(isJsonRpcMessage({ jsonrpc: '2.0', method: 'notifications/initialized' }), true);
});
