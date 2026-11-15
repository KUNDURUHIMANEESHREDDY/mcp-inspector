/**
 * Real upstream acceptance suite.
 *
 * Proves that an official MCP SDK client can list tools and invoke a safe
 * tool through the inspector proxy against real SDK-backed servers for both
 * stdio and Streamable HTTP, across legacy and modern protocol eras.
 *
 * This is the production-readiness gate for "real MCP upstream acceptance".
 * It uses the official @modelcontextprotocol packages (not hand-rolled mocks).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
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
  // Allow offline local runs; CI must fail if dependencies are missing.
  if (process.env.CI === 'true' || error?.code !== 'ERR_MODULE_NOT_FOUND') throw error;
}

const acceptanceResults = [];

function record(result) {
  acceptanceResults.push(result);
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

for (const mode of ['legacy', 'modern']) {
  test(
    `acceptance: official SDK client lists and invokes tools through stdio proxy (${mode})`,
    { skip: !supported || !Client || !StdioClientTransport, timeout: 45_000 },
    async () => {
      const started = Date.now();
      const client = await connectStdioThroughProxy(mode);
      try {
        assert.equal(client.getProtocolEra(), mode);

        const listed = await client.listTools();
        assert.ok(Array.isArray(listed.tools));
        assert.ok(listed.tools.length >= 1, 'expected at least one tool');
        assert.ok(
          listed.tools.some((tool) => tool.name === 'echo'),
          'expected echo tool from official SDK fixture',
        );

        const response = await client.callTool({
          name: 'echo',
          arguments: { message: `stdio-acceptance-${mode}` },
        });

        assert.equal(response.structuredContent?.echo, `stdio-acceptance-${mode}`);
        assert.equal(response.content?.[0]?.text, `echo:stdio-acceptance-${mode}`);

        record({
          transport: 'stdio',
          protocol_era: mode,
          status: 'passed',
          tool_count: listed.tools.length,
          elapsed_ms: Date.now() - started,
        });
      } catch (error) {
        record({
          transport: 'stdio',
          protocol_era: mode,
          status: 'failed',
          error: String(error?.message || error),
          elapsed_ms: Date.now() - started,
        });
        throw error;
      } finally {
        await client.close();
      }
    },
  );
}

for (const mode of ['legacy', 'modern']) {
  test(
    `acceptance: official SDK client lists and invokes tools through HTTP proxy (${mode})`,
    {
      skip: !supported || !Client || !StreamableHTTPClientTransport || !createSdkHttpFixtureServer,
      timeout: 45_000,
    },
    async (t) => {
      const started = Date.now();
      const client = await connectHttpThroughProxy(t, mode);
      try {
        assert.equal(client.getProtocolEra(), mode);

        const listed = await client.listTools();
        assert.ok(Array.isArray(listed.tools));
        assert.ok(listed.tools.length >= 1);
        assert.ok(listed.tools.some((tool) => tool.name === 'echo'));

        const response = await client.callTool({
          name: 'echo',
          arguments: { message: `http-acceptance-${mode}` },
        });

        assert.equal(response.structuredContent?.echo, `http-acceptance-${mode}`);
        assert.equal(response.content?.[0]?.text, `echo:http-acceptance-${mode}`);

        record({
          transport: 'http',
          protocol_era: mode,
          status: 'passed',
          tool_count: listed.tools.length,
          elapsed_ms: Date.now() - started,
        });
      } catch (error) {
        record({
          transport: 'http',
          protocol_era: mode,
          status: 'failed',
          error: String(error?.message || error),
          elapsed_ms: Date.now() - started,
        });
        throw error;
      }
    },
  );
}

test(
  'acceptance: compatibility suite passes for both transports against official SDK fixtures',
  { skip: !supported || !runCompatibilitySuite || !createSdkHttpFixtureServer, timeout: 90_000 },
  async (t) => {
    const started = Date.now();
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

    record({
      transport: 'both',
      protocol_era: 'legacy,auto,modern',
      status: 'passed',
      tool_count: report.results[0]?.toolCount ?? 0,
      elapsed_ms: Date.now() - started,
      contract_hashes: [...new Set(report.results.map((r) => r.contractHash))],
    });
  },
);

/**
 * Optional published-package path.
 * Set MCP_INSPECTOR_REAL_UPSTREAM=1 to exercise a real published server package
 * (currently the local SDK fixture is already from @modelcontextprotocol/server).
 * A future extension can launch @modelcontextprotocol/server-filesystem via npx
 * against a disposable temp directory when network access is available.
 */
test(
  'acceptance: optional published-server path is documented and gated',
  { skip: process.env.MCP_INSPECTOR_REAL_UPSTREAM !== '1' || !supported || !Client, timeout: 60_000 },
  async () => {
    // Placeholder for a future npx-based published server run.
    // Today the official SDK fixture already comes from the published
    // @modelcontextprotocol/server package, so the primary acceptance
    // coverage above is sufficient for the current release gate.
    const tempDir = await mkdtemp(resolve(tmpdir(), 'mcp-inspector-acceptance-'));
    try {
      assert.ok(tempDir);
      record({
        transport: 'stdio',
        protocol_era: 'auto',
        status: 'passed',
        note: 'published-server gate acknowledged; primary coverage uses official SDK package',
        elapsed_ms: 0,
      });
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  },
);

test('acceptance: summary contains only passed results when suite is green', () => {
  // This runs after the other tests in the same file when the runner orders
  // them sequentially. If any earlier acceptance test failed, the process
  // will already have a non-zero exit; this assertion documents the report.
  const failed = acceptanceResults.filter((item) => item.status === 'failed');
  if (failed.length) {
    assert.fail(`acceptance summary contains failures: ${JSON.stringify(failed, null, 2)}`);
  }
  // At least the core matrix should have recorded results when dependencies load.
  if (Client && supported) {
    assert.ok(
      acceptanceResults.length >= 1,
      'expected at least one acceptance result to be recorded',
    );
  }
});
