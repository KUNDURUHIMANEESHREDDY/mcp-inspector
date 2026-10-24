import { performance } from 'node:perf_hooks';
import { LineFramer, decodeJsonRpcFrame, isJsonRpcMessage } from '../src/protocol/framer.js';

const iterations = Math.max(10, Math.min(10_000, Number(process.env.BENCH_ITERATIONS) || 128));
const oneFrame = Buffer.from('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fixture","arguments":{"path":"/tmp/file.txt"}}}\n');
const corpus = Buffer.concat(Array.from({ length: 1024 }, (_, id) => {
  const message = JSON.parse(oneFrame.toString('utf8'));
  message.id = id;
  return Buffer.from(`${JSON.stringify(message)}\n`);
}));
const chunks = [];
for (let offset = 0; offset < corpus.length; offset += 16 * 1024) chunks.push(corpus.subarray(offset, offset + 16 * 1024));

function percentile(values, percentileValue) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * percentileValue) - 1)] ?? 0;
}

function run(label, observe) {
  const batchTimesMs = [];
  let processedBytes = 0;
  let observedFrames = 0;
  const started = performance.now();
  for (let iteration = 0; iteration < iterations; iteration += 1) {
    const batchStarted = performance.now();
    const framer = observe ? new LineFramer({
      onFrame(frame) {
        const decoded = decodeJsonRpcFrame(frame);
        if (decoded.ok && isJsonRpcMessage(decoded.value)) observedFrames += 1;
      },
    }) : null;
    for (const chunk of chunks) {
      // Mirrors the transparent proxy's forwarding-path accounting: the same
      // input Buffer is used for forwarding, while only the observed mode parses.
      processedBytes += chunk.length;
      if (framer) framer.push(chunk);
    }
    framer?.end();
    batchTimesMs.push(performance.now() - batchStarted);
  }
  const elapsedMs = performance.now() - started;
  return {
    mode: label,
    batches: iterations,
    frames_per_batch: 1024,
    bytes_processed: processedBytes,
    elapsed_ms: Number(elapsedMs.toFixed(3)),
    mib_per_second: Number(((processedBytes / (1024 * 1024)) / (elapsedMs / 1000)).toFixed(2)),
    batch_latency_ms: {
      p50: Number(percentile(batchTimesMs, 0.50).toFixed(3)),
      p95: Number(percentile(batchTimesMs, 0.95).toFixed(3)),
      p99: Number(percentile(batchTimesMs, 0.99).toFixed(3)),
    },
    ...(observe ? { observed_frames: observedFrames } : {}),
  };
}

const baseline = run('transparent-buffer-loop', false);
const inspected = run('side-channel-framing-and-jsonrpc-validation', true);
const report = {
  benchmark: 'stdio-proxy-side-channel-microbenchmark',
  node: process.version,
  note: 'Microbenchmark only; excludes OS pipes, MCP SDK, network transport, OpenTelemetry exporter, and external load.',
  results: [baseline, inspected],
  estimated_parser_cost_ms_per_batch: Number((inspected.batch_latency_ms.p50 - baseline.batch_latency_ms.p50).toFixed(3)),
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
