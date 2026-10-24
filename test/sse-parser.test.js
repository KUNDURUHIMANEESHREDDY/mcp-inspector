import test from 'node:test';
import assert from 'node:assert/strict';
import { SseObserver } from '../src/protocol/sse-parser.js';

test('SSE observer parses fragmented data events and ignores comments and [DONE]', () => {
  const seen = [];
  const observer = new SseObserver((frame) => seen.push(frame.toString('utf8')));
  observer.push(Buffer.from(': heartbeat\n\n data: ignored\n\ndata: {"jsonrpc":"2.0",'));
  observer.push(Buffer.from('"id":1,"result":{"ok":true}}\n\ndata: [DONE]\n\n'));
  observer.end();
  assert.deepEqual(seen, ['{"jsonrpc":"2.0","id":1,"result":{"ok":true}}']);
});

test('SSE observer handles a UTF-8 code point split across byte chunks', () => {
  const seen = [];
  const observer = new SseObserver((frame) => seen.push(frame.toString('utf8')));
  const bytes = Buffer.from('data: {"text":"🌍"}\n\n');
  const split = bytes.indexOf(Buffer.from('🌍')) + 2;
  observer.push(bytes.subarray(0, split));
  observer.push(bytes.subarray(split));
  observer.end();
  assert.deepEqual(seen, ['{"text":"🌍"}']);
});

test('SSE observer drops events beyond its configured inspection cap', () => {
  const seen = [];
  const warnings = [];
  const observer = new SseObserver((frame) => seen.push(frame.toString('utf8')), {
    maxEventBytes: 1024,
    onOversize: (details) => warnings.push(details),
  });
  observer.push(Buffer.concat([Buffer.from('data: '), Buffer.alloc(1100, 0x78), Buffer.from('\n\ndata: {"ok":true}\n\n')]));
  observer.end();
  assert.equal(warnings.length, 1);
  assert.deepEqual(seen, ['{"ok":true}']);
});
