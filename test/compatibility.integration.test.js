import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
let runCompatibilitySuite;
let createSdkHttpFixtureServer;
try {
  ({ runCompatibilitySuite } = await import('../src/compatibility/suite.js'));
  ({ createSdkHttpFixtureServer } = await import('../fixtures/sdk-http-mcp-server.js'));
} catch (error) {
  if (process.env.CI === 'true' || error?.code !== 'ERR_MODULE_NOT_FOUND') throw error;
}

test('compatibility probes legacy, auto, and modern stdio against the official SDK fixture', { skip: !runCompatibilitySuite, timeout: 60_000 }, async () => {
  const report = await runCompatibilitySuite({
    transports: ['stdio'], protocols: ['legacy', 'auto', 'modern'],
    command: process.execPath, args: [resolve(root, 'fixtures/sdk-mcp-server.js')], timeoutMs: 15_000,
  });
  assert.equal(report.summary.total, 3);
  assert.equal(report.summary.passed, 3, JSON.stringify(report.results));
  assert.ok(report.results.every((result) => result.contractHash && result.toolCount >= 1));
  assert.equal(report.readOnly, true);
});

test('compatibility probes legacy, auto, and modern Streamable HTTP', { skip: !runCompatibilitySuite || !createSdkHttpFixtureServer, timeout: 60_000 }, async (t) => {
  const server = createSdkHttpFixtureServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolveClose) => server.close(resolveClose)));
  const address = server.address();
  const report = await runCompatibilitySuite({
    transports: ['http'], protocols: ['legacy', 'auto', 'modern'],
    url: 'http://127.0.0.1:' + address.port + '/mcp', timeoutMs: 15_000,
  });
  assert.equal(report.summary.total, 3);
  assert.equal(report.summary.passed, 3, JSON.stringify(report.results));
  assert.ok(report.results.every((result) => result.contractHash && result.toolCount >= 1));
});

test('compatibility validation rejects URL credentials and invalid timeouts', { skip: !runCompatibilitySuite }, async () => {
  await assert.rejects(runCompatibilitySuite({ transports: ['http'], url: 'http://user:password@127.0.0.1:3000/mcp' }), /Credentials in endpoint URLs are not allowed/);
  await assert.rejects(runCompatibilitySuite({ transports: ['stdio'], command: process.execPath, timeoutMs: 0 }), /timeoutMs must be an integer/);
});
