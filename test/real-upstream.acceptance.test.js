/**
 * Real upstream acceptance suite.
 *
 * Proves that an official MCP SDK client can list tools and invoke a safe
 * tool through the inspector proxy against real SDK-backed servers for both
 * stdio and Streamable HTTP, across legacy and modern protocol eras.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { startHttpProxy } from '../src/proxy/http.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const supported = Number(process.versions.node.split('.')[0]) >= 22;

let Client;
let StdioClientTransport;
let StreamableHTTPClientTransport;
let createSdkHttpFixtureServer;
let runCompatibilitySuite;

try {
  ({ Client } = await import('@modelcontextprotocol/client'));
  ({ StdioClientTransport } = await import('@modelcontextprotocol/client/stdio'));
  ({ StreamableHTTPClientTransport } = await import('@modelcontextprotocol/client'));
  ({ createSdkHttpFixtureServer } = await import('../fixtures/sdk-http-mcp-server.js'));
  ({ runCompatibilitySuite } = await import('../src/compatibility/suite.js'));
} catch (error) {
  if (process.env.CI === 'true' || error?.code !== 'ERR_MODULE_NOT_FOUND') throw error;
}

async function connectStdioThroughProxy(mode = 'legacy') {
  const options = mode === 'modern' ? { versionNegotiation: { mode: { pin: '2026-07-28' } } } : {};
  const client = new Client({ name: 'mcp-inspector-acceptance', version: '1.0.0' }, options);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      resolve(root, 'src/cli.js'),
      'proxy',
      '--',
      process.execPath,
      resolve(root, 'fixtures/sdk-mcp-server.js'),
    ],
    env: { ...process.env, MCP_INSPECTOR_LOG_LEVEL: 'error' },
  });
  await client.connect(transport);
  return client;
}

async function connectHttpThroughProxy(t, mode = 'legacy') {
  const upstream = createSdkHttpFixtureServer();
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const upstreamAddress = upstream.address();

  const proxy = startHttpProxy({
    upstream: `http://127.0.0.1:${upstreamAddress.port}`,
    listen: '127.0.0.1:0',
  });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyAddress = proxy.server.address();

  const options = mode === 'modern' ? { versionNegotiation: { mode: { pin: '2026-07-28' } } } : {};
  const client = new Client({ name: 'mcp-inspector-http-acceptance', version: '1.0.0' }, options);

  t.after(async () => {
    try {
      await client.close();
    } catch {
      /* may not have connected */
    }
    await proxy.close();
    await new Promise((resolveClose) => upstream.close(resolveClose));
  });

  const transport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${proxyAddress.port}/mcp`),
  );
  await client.connect(transport);
  return client;
}

describe('real upstream acceptance', { concurrency: false }, () => {
  for (const mode of ['legacy', 'modern']) {
    test(
      `stdio proxy lists and invokes tools (${mode})`,
      { skip: !supported || !Client || !StdioClientTransport, timeout: 45_000 },
      async () => {
        const client = await connectStdioThroughProxy(mode);
        try {
          if (typeof client.getProtocolEra === 'function') {
            assert.equal(client.getProtocolEra(), mode);
          }
          const listed = await client.listTools();
          assert.ok(Array.isArray(listed.tools));
          assert.ok(listed.tools.some((tool) => tool.name === 'echo'));
          const response = await client.callTool({
            name: 'echo',
            arguments: { message: `stdio-acceptance-${mode}` },
          });
          assert.equal(response.structuredContent?.echo, `stdio-acceptance-${mode}`);
          assert.equal(response.content?.[0]?.text, `echo:stdio-acceptance-${mode}`);
        } finally {
          await client.close();
        }
      },
    );
  }

  for (const mode of ['legacy', 'modern']) {
    test(
      `HTTP proxy lists and invokes tools (${mode})`,
      {
        skip: !supported || !Client || !StreamableHTTPClientTransport || !createSdkHttpFixtureServer,
        timeout: 45_000,
      },
      async (t) => {
        const client = await connectHttpThroughProxy(t, mode);
        if (typeof client.getProtocolEra === 'function') {
          assert.equal(client.getProtocolEra(), mode);
        }
        const listed = await client.listTools();
        assert.ok(Array.isArray(listed.tools));
        assert.ok(listed.tools.some((tool) => tool.name === 'echo'));
        const response = await client.callTool({
          name: 'echo',
          arguments: { message: `http-acceptance-${mode}` },
        });
        assert.equal(response.structuredContent?.echo, `http-acceptance-${mode}`);
        assert.equal(response.content?.[0]?.text, `echo:http-acceptance-${mode}`);
      },
    );
  }

  test(
    'compatibility suite passes for both transports against official SDK fixtures',
    { skip: !supported || !runCompatibilitySuite || !createSdkHttpFixtureServer, timeout: 90_000 },
    async (t) => {
      const server = createSdkHttpFixtureServer();
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      t.after(() => new Promise((resolveClose) => server.close(resolveClose)));

      const address = server.address();
      const report = await runCompatibilitySuite({
        transports: ['stdio', 'http'],
        protocols: ['legacy', 'auto', 'modern'],
        command: process.execPath,
        args: [resolve(root, 'fixtures/sdk-mcp-server.js')],
        url: `http://127.0.0.1:${address.port}/mcp`,
        timeoutMs: 15_000,
      });

      assert.equal(report.readOnly, true);
      assert.equal(report.summary.total, 6);
      assert.equal(
        report.summary.passed,
        6,
        `compatibility acceptance failed: ${JSON.stringify(report.results, null, 2)}`,
      );
      assert.ok(report.results.every((result) => result.contractHash && result.toolCount >= 1));
    },
  );
});
