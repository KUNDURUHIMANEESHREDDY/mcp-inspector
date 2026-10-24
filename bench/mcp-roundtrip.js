#!/usr/bin/env node
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixture = resolve(root, 'fixtures/sdk-mcp-server.js');
const cli = resolve(root, 'src/cli.js');
const samples = Math.max(25, Math.min(2_000, Number(process.env.MCP_INSPECTOR_BENCH_SAMPLES) || 150));

function quantile(values, p) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1)] ?? 0;
}

async function connectThrough(command, args) {
  const client = new Client({ name: 'mcp-inspector-benchmark', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command,
    args,
    env: { ...process.env, MCP_INSPECTOR_LOG_LEVEL: 'error' },
  });
  await client.connect(transport);
  return client;
}

async function measure(label, client) {
  const latencies = [];
  for (let index = 0; index < 10; index += 1) {
    await client.callTool({ name: 'echo', arguments: { message: `warmup-${index}` } }, { timeout: 10_000 });
  }
  for (let index = 0; index < samples; index += 1) {
    const started = performance.now();
    const result = await client.callTool({ name: 'echo', arguments: { message: `sample-${index}` } }, { timeout: 10_000 });
    const elapsed = performance.now() - started;
    if (result?.isError || result?.structuredContent?.echo !== `sample-${index}`) {
      throw new Error(`${label}: fixture call returned an unexpected result`);
    }
    latencies.push(elapsed);
  }
  return {
    mode: label,
    samples,
    protocol_era: client.getProtocolEra?.() ?? 'legacy-or-unknown',
    latency_ms: {
      p50: Number(quantile(latencies, 0.50).toFixed(3)),
      p95: Number(quantile(latencies, 0.95).toFixed(3)),
      p99: Number(quantile(latencies, 0.99).toFixed(3)),
      mean: Number((latencies.reduce((sum, value) => sum + value, 0) / latencies.length).toFixed(3)),
    },
  };
}

let direct;
let observed;
try {
  const directClient = await connectThrough(process.execPath, [fixture]);
  try { direct = await measure('direct-sdk-server', directClient); }
  finally { await directClient.close(); }

  const proxyClient = await connectThrough(process.execPath, [cli, 'proxy', '--', process.execPath, fixture]);
  try { observed = await measure('through-mcp-inspector', proxyClient); }
  finally { await proxyClient.close(); }
} catch (error) {
  process.stderr.write(`Round-trip benchmark failed: ${error?.name ?? 'Error'}\n`);
  process.exitCode = 1;
}

if (direct && observed) {
  process.stdout.write(`${JSON.stringify({
    benchmark: 'mcp-sdk-stdio-round-trip',
    node: process.version,
    samples_per_mode: samples,
    note: 'Serial round-trips against a local no-op fixture; compare on the same machine. Not a production load test.',
    results: [direct, observed],
    proxy_overhead_ms: {
      p50: Number((observed.latency_ms.p50 - direct.latency_ms.p50).toFixed(3)),
      p95: Number((observed.latency_ms.p95 - direct.latency_ms.p95).toFixed(3)),
      p99: Number((observed.latency_ms.p99 - direct.latency_ms.p99).toFixed(3)),
    },
  }, null, 2)}\n`);
}
