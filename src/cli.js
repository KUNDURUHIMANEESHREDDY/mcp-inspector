#!/usr/bin/env node
import { readFile, stat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { startStdioProxy } from './proxy/stdio.js';
import { startHttpProxy } from './proxy/http.js';
import { initializeTelemetry, shutdownTelemetry } from './observability/telemetry.js';
import { compareContracts, readContract } from './contracts/contract.js';
import { log, logError } from './observability/logger.js';
import { startDashboardServer } from './dashboard/server.js';

const require = createRequire(import.meta.url);
const packageInfo = require('../package.json');

const HELP = `
MCP Inspector ${packageInfo.version}
Protocol-level observability, contract drift detection, and schema-driven fuzzing.

Usage:
  mcp-inspector proxy [options] -- <server-command> [args...]
  mcp-inspector snapshot --output <contract.json> [--protocol legacy|auto|modern] -- <server-command> [args...]
  mcp-inspector fuzz [--case-mode valid|invalid|mixed] [--max-cases 30] [--protocol legacy|auto|modern] [--execute --allow-side-effects] -- <server-command> [args...]
  mcp-inspector workflow --file <workflow.json> [--execute --allow-side-effects] -- <server-command> [args...]
  mcp-inspector contract-diff --baseline <old.json> --current <new.json>
  mcp-inspector compat --transport stdio -- <server-command> [args...]
  mcp-inspector compat --transport http --url <http-url>
  mcp-inspector compat --transport both --url <http-url> -- <server-command> [args...]
  mcp-inspector dashboard --upstream <url> [--proxy-listen 127.0.0.1:9900] [--dashboard-listen 127.0.0.1:9911]
  mcp-inspector dashboard --stdio [--dashboard-listen 127.0.0.1:9911] -- <server-command> [args...]
  mcp-inspector help

Dashboard:
  The dashboard is local-only and read-only. It displays sanitized metadata from the same process.
  Use exactly one of --upstream or --stdio. Browser reports are parsed locally, never uploaded.

Proxy options:
  --upstream <origin>          HTTP reverse proxy mode (e.g. http://127.0.0.1:3000)
  --listen <host:port>         HTTP listen endpoint; default 127.0.0.1:9900
  --allow-remote               Permit a non-loopback HTTP listener (not recommended without a gateway)
  --contract-file <path>       Capture/diff tools/list schema in this file
  --contract-source <name>     Stable label for the server in contract reports
  --update-contract            Replace the stored baseline after a comparison

Compatibility:
  compat is read-only. It initializes and lists tools; it never invokes server tools.
  Use --transport both to check stdio and Streamable HTTP in the same report.
  --timeout-ms accepts 100-120000; fuzz/workflow --max-duration-ms accepts 1000-900000.

Safety:
  Fuzzing is dry-run by default. Real tool calls require BOTH --execute and
  --allow-side-effects. Tool calls can mutate files or invoke external systems.
  HTTP proxy mode binds to loopback unless --allow-remote is explicitly set.
  Logs contain metadata only; request arguments and tool results are not logged.

Protocol modes:
  legacy                       Use the initialize handshake (default)
  auto                         Probe modern and fall back to legacy
  modern                       Require MCP protocol revision 2026-07-28

Environment:
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT  Optional OTLP/HTTP trace exporter URL
  OTEL_SERVICE_NAME                   OpenTelemetry service name
  MCP_INSPECTOR_MAX_FRAME_BYTES       Maximum observed frame size (default 16 MiB)
  MCP_INSPECTOR_LOG_LEVEL             debug|info|warn|error (default info)
`;

function ensureSupportedNode() {
  const major = Number(process.versions.node.split('.')[0]);
  if (major < 22) {
    throw new Error(`Node.js >=22 is required for this release. Current runtime: ${process.versions.node}`);
  }
}

function splitOptionsAndCommand(args) {
  const separator = args.indexOf('--');
  return {
    optionArgs: separator === -1 ? args : args.slice(0, separator),
    commandArgs: separator === -1 ? [] : args.slice(separator + 1),
  };
}

function parseOptions(args, schema) {
  const options = {};
  const booleanFlags = new Set(schema.boolean ?? []);
  const valueFlags = new Set(schema.value ?? []);
  const { optionArgs, commandArgs } = splitOptionsAndCommand(args);
  for (let index = 0; index < optionArgs.length; index += 1) {
    const token = optionArgs[index];
    if (!token.startsWith('--')) throw new Error(`Unexpected argument: ${token}`);
    const flag = token.slice(2);
    if (booleanFlags.has(flag)) {
      options[toCamelCase(flag)] = true;
      continue;
    }
    if (!valueFlags.has(flag)) throw new Error(`Unknown option: ${token}`);
    const value = optionArgs[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${token} requires a value`);
    options[toCamelCase(flag)] = value;
    index += 1;
  }
  options.commandArgs = commandArgs;
  return options;
}

function toCamelCase(value) {
  return value.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}

function requireSafetyConsent(options) {
  if (options.allowSideEffects && !options.execute) throw new Error('--allow-side-effects requires --execute');
  if (options.execute && !options.allowSideEffects) throw new Error('Tool execution requires BOTH --execute and --allow-side-effects');
}

function parseMaxCases(value) {
  const parsed = Number(value ?? 30);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 500) throw new Error('--max-cases must be an integer from 1 to 500');
  return parsed;
}

function parseBoundedInteger(value, defaultValue, min, max, optionName) {
  const parsed = Number(value ?? defaultValue);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) throw new Error(optionName + ' must be an integer from ' + min + ' to ' + max);
  return parsed;
}

function protocolOption(options) {
  const protocol = options.protocol ?? 'legacy';
  if (!['legacy', 'auto', 'modern'].includes(protocol)) throw new Error('--protocol must be legacy, auto, or modern');
  return protocol;
}

async function printJson(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

async function commandProxy(args) {
  const options = parseOptions(args, {
    boolean: ['allow-remote', 'update-contract'],
    value: ['upstream', 'listen', 'contract-file', 'contract-source'],
  });
  if (options.upstream) {
    const proxy = startHttpProxy(options);
    await new Promise((resolveDone) => {
      const stop = () => {
        void proxy.close().then(resolveDone);
      };
      const cleanup = () => {
        process.removeListener('SIGINT', onInterrupt);
        process.removeListener('SIGTERM', onTerminate);
      };
      const onInterrupt = () => { cleanup(); stop(); };
      const onTerminate = () => { cleanup(); stop(); };
      proxy.server.once('close', cleanup);
      process.once('SIGINT', onInterrupt);
      process.once('SIGTERM', onTerminate);
    });
    return;
  }
  if (options.allowRemote || options.listen) throw new Error('--listen and --allow-remote apply only with --upstream');
  const proxy = startStdioProxy(options.commandArgs[0], options.commandArgs.slice(1), options);
  await proxy.done;
}

async function commandDashboard(args) {
  const options = parseOptions(args, {
    boolean: ['stdio', 'update-contract'],
    value: ['upstream', 'proxy-listen', 'dashboard-listen', 'contract-file', 'contract-source'],
  });
  const useStdio = options.stdio === true;
  const useHttp = typeof options.upstream === 'string';
  if (useStdio === useHttp) throw new Error('Choose exactly one dashboard mode: --stdio or --upstream <url>');
  if (useStdio && !options.commandArgs.length) throw new Error('A server command is required after -- in --stdio mode');
  if (useHttp && options.commandArgs.length) throw new Error('HTTP dashboard mode does not take a server command after --');
  if (options.proxyListen && !useHttp) throw new Error('--proxy-listen applies only with --upstream');
  const dashboard = await startDashboardServer({
    listen: options.dashboardListen ?? '127.0.0.1:9911',
    version: packageInfo.version,
  });
  let proxy;
  try {
    if (useStdio) {
      proxy = startStdioProxy(options.commandArgs[0], options.commandArgs.slice(1), options);
      log('info', 'dashboard.started', { dashboard_url: dashboard.url, transport: 'stdio' });
      await proxy.done;
    } else {
      proxy = startHttpProxy({
        upstream: options.upstream,
        listen: options.proxyListen ?? '127.0.0.1:9900',
        contractFile: options.contractFile,
        contractSource: options.contractSource,
        updateContract: options.updateContract === true,
      });
      log('info', 'dashboard.started', { dashboard_url: dashboard.url, transport: 'http' });
      await new Promise((resolveDone) => {
        let stopping = false;
        const cleanup = () => {
          process.removeListener('SIGINT', stop);
          process.removeListener('SIGTERM', stop);
          proxy.server.removeListener('close', onClose);
        };
        const stop = () => {
          if (stopping) return;
          stopping = true;
          cleanup();
          void proxy.close().finally(resolveDone);
        };
        const onClose = () => {
          cleanup();
          resolveDone();
        };
        process.once('SIGINT', stop);
        process.once('SIGTERM', stop);
        proxy.server.once('close', onClose);
      });
    }
  } finally {
    if (useHttp && proxy) await proxy.close();
    await dashboard.close();
  }
}

async function commandSnapshot(args) {
  const options = parseOptions(args, { value: ['output', 'protocol'] });
  if (!options.output) throw new Error('--output is required');
  if (!options.commandArgs.length) throw new Error('A server command is required after `--`');
  const { snapshotServer } = await import('./fuzz/client.js');
  const contract = await snapshotServer({
    command: options.commandArgs[0],
    args: options.commandArgs.slice(1),
    protocol: protocolOption(options),
    output: resolve(options.output),
  });
  await printJson({ output: resolve(options.output), tool_count: contract.tools.length, hash: contract.hash, protocol_era: contract.protocolEra });
}

async function commandFuzz(args) {
  const options = parseOptions(args, {
    boolean: ['execute', 'allow-side-effects', 'progress'],
    value: ['max-cases', 'protocol', 'case-mode', 'timeout-ms', 'max-duration-ms'],
  });
  requireSafetyConsent(options);
  if (!options.commandArgs.length) throw new Error('A server command is required after --');
  const caseMode = options.caseMode ?? 'valid';
  if (!['valid', 'invalid', 'mixed'].includes(caseMode)) throw new Error('--case-mode must be valid, invalid, or mixed');
  const maxCases = parseMaxCases(options.maxCases);
  if (caseMode === 'mixed' && maxCases < 2) throw new Error('--max-cases must be at least 2 for --case-mode mixed');
  const { fuzzServer } = await import('./fuzz/client.js');
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  let report;
  try {
    report = await fuzzServer({
      command: options.commandArgs[0], args: options.commandArgs.slice(1),
      protocol: protocolOption(options), maxCases, caseMode, execute: options.execute === true,
      timeoutMs: parseBoundedInteger(options.timeoutMs, 15_000, 100, 120_000, '--timeout-ms'),
      maxDurationMs: parseBoundedInteger(options.maxDurationMs, 300_000, 1_000, 900_000, '--max-duration-ms'),
      signal: controller.signal,
      onProgress: options.progress ? (event) => process.stderr.write(JSON.stringify({ event: 'workbench.progress', ...event }) + '\n') : undefined,
    });
  } finally {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
  await printJson(report);
  if (report.cancelled) process.exitCode = 130;
  else if (report.limitReached || report.tools.some((tool) => tool.results?.some((result) => ['protocol_error', 'timeout'].includes(result.outcome)))) process.exitCode = 1;
}
async function commandWorkflow(args) {
  const options = parseOptions(args, {
    boolean: ['execute', 'allow-side-effects', 'progress'],
    value: ['file', 'protocol', 'timeout-ms', 'max-duration-ms'],
  });
  requireSafetyConsent(options);
  if (!options.file) throw new Error('--file is required');
  if (!options.commandArgs.length) throw new Error('A server command is required after --');
  const workflowPath = resolve(options.file);
  const metadata = await stat(workflowPath);
  if (metadata.size > 1_048_576) throw new Error('Workflow file exceeds the 1 MiB safety limit');
  const workflow = JSON.parse(await readFile(workflowPath, 'utf8'));
  if (!Array.isArray(workflow.steps) || workflow.steps.length < 1 || workflow.steps.length > 500) throw new Error('Workflow JSON must include between 1 and 500 steps');
  const { runWorkflow } = await import('./fuzz/client.js');
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  let report;
  try {
    report = await runWorkflow({
      command: options.commandArgs[0], args: options.commandArgs.slice(1),
      protocol: protocolOption(options), workflow, execute: options.execute === true,
      timeoutMs: parseBoundedInteger(options.timeoutMs, 30_000, 100, 120_000, '--timeout-ms'),
      maxDurationMs: parseBoundedInteger(options.maxDurationMs, 300_000, 1_000, 900_000, '--max-duration-ms'),
      signal: controller.signal,
      onProgress: options.progress ? (event) => process.stderr.write(JSON.stringify({ event: 'workbench.progress', ...event }) + '\n') : undefined,
    });
  } finally {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
  await printJson(report);
  if (report.cancelled) process.exitCode = 130;
  else if (report.limitReached || report.steps.some((step) => ['protocol_error', 'timeout', 'unknown_tool', 'skipped_invalid_arguments'].includes(step.outcome))) process.exitCode = 1;
}
async function commandCompatibility(args) {
  const options = parseOptions(args, { value: ['transport', 'url', 'protocols', 'timeout-ms'] });
  const transport = options.transport ?? (options.url ? 'http' : 'stdio');
  if (!['stdio', 'http', 'both'].includes(transport)) throw new Error('--transport must be stdio, http, or both');
  const transports = transport === 'both' ? ['stdio', 'http'] : [transport];
  if (transports.includes('http') && !options.url) throw new Error('--url is required for HTTP compatibility checks');
  if (transports.includes('stdio') && !options.commandArgs.length) throw new Error('A server command is required after -- for stdio compatibility checks');
  if (!transports.includes('stdio') && options.commandArgs.length) throw new Error('HTTP compatibility checks do not take a server command after --');
  const protocols = (options.protocols ?? 'legacy,auto,modern').split(',').map((item) => item.trim()).filter(Boolean);
  const { runCompatibilitySuite } = await import('./compatibility/suite.js');
  const report = await runCompatibilitySuite({
    transports, protocols, command: options.commandArgs[0], args: options.commandArgs.slice(1), url: options.url,
    timeoutMs: parseBoundedInteger(options.timeoutMs, 15_000, 100, 120_000, '--timeout-ms'),
  });
  await printJson(report);
  if (!report.summary.success) process.exitCode = 1;
}

async function commandContractDiff(args) {
  const options = parseOptions(args, { value: ['baseline', 'current'] });
  if (!options.baseline || !options.current) throw new Error('--baseline and --current are required');
  const [baseline, current] = await Promise.all([readContract(resolve(options.baseline)), readContract(resolve(options.current))]);
  const report = compareContracts(baseline, current);
  await printJson({ baseline: resolve(options.baseline), current: resolve(options.current), ...report });
  process.exitCode = report.breaking ? 1 : 0;
}

async function commandInspect(args) {
  // Quick transport-independent inspect mode: read JSONL from stdin and print sanitized summaries.
  // Kept separate from `proxy`, which must reserve stdout for MCP protocol data.
  if (args.length) throw new Error('inspect reads JSONL from stdin and does not accept options');
  const { MessageInspector } = await import('./protocol/inspector.js');
  const inspector = new MessageInspector({ direction: 'client_to_server', transport: 'stdin-jsonl' });
  for await (const line of process.stdin) await inspector.observeFrame(Buffer.from(line));
  inspector.end();
}

async function main() {
  const [command = 'help', ...args] = process.argv.slice(2);
  if (['help', '--help', '-h'].includes(command)) {
    process.stdout.write(`${HELP.trim()}\n`);
    return;
  }
  if (['version', '--version', '-v'].includes(command)) {
    process.stdout.write(`${packageInfo.version}\n`);
    return;
  }
  ensureSupportedNode();
  await initializeTelemetry();
  try {
    switch (command) {
      case 'proxy': await commandProxy(args); break;
      case 'dashboard': await commandDashboard(args); break;
      case 'snapshot': await commandSnapshot(args); break;
      case 'fuzz': await commandFuzz(args); break;
      case 'workflow': await commandWorkflow(args); break;
      case 'contract-diff': await commandContractDiff(args); break;
      case 'compat': await commandCompatibility(args); break;
      case 'inspect': await commandInspect(args); break;
      default: throw new Error(`Unknown command '${command}'. Run 'mcp-inspector help'.`);
    }
  } finally {
    await shutdownTelemetry();
  }
}

main().catch((error) => {
  logError('cli.failed', error, { command: process.argv[2] || 'help' });
  process.stderr.write(`MCP Inspector failed: ${error?.message ?? 'unknown error'}\nRun 'mcp-inspector help' for usage.\n`);
  process.exitCode = 2;
});
