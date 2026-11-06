import test from 'node:test';
import assert from 'node:assert/strict';
let MessageInspector;
let readMaxFrameBytes;
try {
  ({ MessageInspector, readMaxFrameBytes } = await import('../src/protocol/inspector.js'));
} catch {
  // Skip when runtime dependencies have not been installed in this isolated build environment.
}

test('request and response inspectors share correlation state by scope', { skip: !MessageInspector }, async () => {
  const pendingStore = new Map();
  const contractRecorder = { observeToolsList: async () => {} };
  const common = { transport: 'test', pendingStore, contractRecorder, correlationScope: 'session:test', contractScope: 'fixture' };
  const ingress = new MessageInspector({ ...common, direction: 'client_to_server' });
  const egress = new MessageInspector({ ...common, direction: 'server_to_client' });
  await ingress.observeFrame(Buffer.from('{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"fixture.txt"}}}'));
  await egress.observeFrame(Buffer.from('{"jsonrpc":"2.0","id":7,"method":"sampling/createMessage","params":{}}'));
  assert.equal(pendingStore.size, 2, 'opposite-direction requests with the same id must not collide');
  await ingress.observeFrame(Buffer.from('{"jsonrpc":"2.0","id":7,"result":{"content":[]}}'));
  assert.equal(pendingStore.size, 1, 'client response should finish the server-initiated request');
  await egress.observeFrame(Buffer.from('{"jsonrpc":"2.0","id":7,"result":{"content":[]}}'));
  assert.equal(pendingStore.size, 0, 'server response should finish the client-initiated request');
});

test('frame-size configuration fails closed and stays within documented bounds', { skip: !readMaxFrameBytes }, () => {
  const previous = process.env.MCP_INSPECTOR_MAX_FRAME_BYTES;
  try {
    delete process.env.MCP_INSPECTOR_MAX_FRAME_BYTES;
    assert.equal(readMaxFrameBytes(), 16 * 1024 * 1024);

    process.env.MCP_INSPECTOR_MAX_FRAME_BYTES = '1024';
    assert.equal(readMaxFrameBytes(), 1024);
    process.env.MCP_INSPECTOR_MAX_FRAME_BYTES = '67108864';
    assert.equal(readMaxFrameBytes(), 64 * 1024 * 1024);

    for (const value of ['1023', '67108865', '', 'not-a-number', '1e6', '0x1000', '1.5', ' 1024 ']) {
      process.env.MCP_INSPECTOR_MAX_FRAME_BYTES = value;
      assert.throws(
        () => readMaxFrameBytes(),
        /MCP_INSPECTOR_MAX_FRAME_BYTES must be an integer between 1024 and 67108864/,
        `invalid frame cap should fail startup: ${JSON.stringify(value)}`,
      );
    }
  } finally {
    if (previous === undefined) delete process.env.MCP_INSPECTOR_MAX_FRAME_BYTES;
    else process.env.MCP_INSPECTOR_MAX_FRAME_BYTES = previous;
  }
});
