import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { once } from 'node:events';
import { startHttpProxy } from '../src/proxy/http.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
let Client;
let StdioClientTransport;
let StreamableHTTPClientTransport;
let fuzzServer;
let createSdkHttpFixtureServer;
try {
  ({ Client } = await import('@modelcontextprotocol/client'));
  ({ StdioClientTransport } = await import('@modelcontextprotocol/client/stdio'));
  ({ StreamableHTTPClientTransport } = await import('@modelcontextprotocol/client'));
  ({ fuzzServer } = await import('../src/fuzz/client.js'));
  ({ createSdkHttpFixtureServer } = await import('../fixtures/sdk-http-mcp-server.js'));
} catch (error) {
  // Allow an offline local test run; CI must fail if dependencies are missing or broken.
  if (process.env.CI === 'true' || error?.code !== 'ERR_MODULE_NOT_FOUND') throw error;
}

async function connectThroughProxy(mode = 'legacy') {
  const options = mode === 'modern' ? { versionNegotiation: { mode: { pin: '2026-07-28' } } } : {};
  const client = new Client({ name: 'mcp-inspector-integration-test', version: '1.0.0' }, options);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      resolve(root, 'src/cli.js'), 'proxy', '--', process.execPath,
      resolve(root, 'fixtures/sdk-mcp-server.js'),
    ],
    env: { ...process.env, MCP_INSPECTOR_LOG_LEVEL: 'error' },
  });
  await client.connect(transport);
  return client;
}

for (const mode of ['legacy', 'modern']) {
  test(`official MCP SDK client lists and invokes a real SDK server through the proxy (${mode})`, { skip: !Client, timeout: 30_000 }, async () => {
    const client = await connectThroughProxy(mode);
    try {
      assert.equal(client.getProtocolEra(), mode);
      const listed = await client.listTools();
      assert.ok(listed.tools.some((tool) => tool.name === 'echo'));
      const response = await client.callTool({ name: 'echo', arguments: { message: 'protocol-ok' } });
      assert.equal(response.structuredContent.echo, 'protocol-ok');
      assert.equal(response.content[0].text, 'echo:protocol-ok');
    } finally {
      await client.close();
    }
  });
}

test('schema-driven fuzzing produces valid and invalid candidates without executing them by default', { skip: !fuzzServer, timeout: 30_000 }, async () => {
  const report = await fuzzServer({
    command: process.execPath,
    args: [resolve(root, 'fixtures/sdk-mcp-server.js')],
    protocol: 'auto',
    maxCases: 10,
    caseMode: 'mixed',
    execute: false,
  });
  assert.equal(report.dryRun, true);
  assert.equal(report.executed, 0);
  assert.ok(report.tools.some((tool) => tool.cases.some((item) => item.valid_by_schema)));
  assert.ok(report.tools.some((tool) => tool.cases.some((item) => !item.valid_by_schema)));
});


async function connectThroughHttpProxy(t, mode = 'legacy') {
  const upstream = createSdkHttpFixtureServer();
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const upstreamAddress = upstream.address();
  const proxy = startHttpProxy({ upstream: `http://127.0.0.1:${upstreamAddress.port}`, listen: '127.0.0.1:0' });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyAddress = proxy.server.address();
  const options = mode === 'modern' ? { versionNegotiation: { mode: { pin: '2026-07-28' } } } : {};
  const client = new Client({ name: 'mcp-inspector-http-integration-test', version: '1.0.0' }, options);
  t.after(async () => {
    try { await client.close(); } catch { /* Client may not have connected. */ }
    await proxy.close();
    await new Promise((resolvePromise) => upstream.close(resolvePromise));
  });
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${proxyAddress.port}/mcp`));
  await client.connect(transport);
  return client;
}

for (const mode of ['legacy', 'modern']) {
  test(`official MCP SDK client invokes the official SDK HTTP server through the proxy (${mode})`, {
    skip: !Client || !StreamableHTTPClientTransport || !createSdkHttpFixtureServer,
    timeout: 30_000,
  }, async (t) => {
    const client = await connectThroughHttpProxy(t, mode);
    assert.equal(client.getProtocolEra(), mode);
    const listed = await client.listTools();
    assert.ok(listed.tools.some((tool) => tool.name === 'echo'));
    const response = await client.callTool({ name: 'echo', arguments: { message: 'http-protocol-ok' } });
    assert.equal(response.structuredContent.echo, 'http-protocol-ok');
    assert.equal(response.content[0].text, 'echo:http-protocol-ok');
  });
}

test('fuzz execution honours cancellation before generating cases or invoking tools', { skip: !fuzzServer, timeout: 30_000 }, async () => {
  const controller = new AbortController();
  controller.abort();
  const report = await fuzzServer({
    command: process.execPath,
    args: [resolve(root, 'fixtures/sdk-mcp-server.js')],
    maxCases: 10,
    caseMode: 'mixed',
    execute: true,
    signal: controller.signal,
  });
  assert.equal(report.cancelled, true);
  assert.equal(report.executed, 0);
  assert.equal(report.totalCandidates, 0);
});
