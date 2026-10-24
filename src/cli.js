#!/usr/bin/env node
import { readFile, stat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { startStdioProxy } from './proxy/stdio.js';
import { startHttpProxy } from './proxy/http.js';
import { initializeTelemetry, shutdownTelemetry } from './observability/telemetry.js';
import { compareContracts, readContract } from './contracts/contract.js';
import { logError } from './observability/logger.js';

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
  mcp-inspector help

Proxy options:
  --upstream <origin>          HTTP reverse proxy mode (e.g. http://127.0.0.1:3000)
  --listen <host:port>         HTTP listen endpoint; default 127.0.0.1:9900
  --allow-remote               Permit a non-loopback HTTP listener (not recommended without a gateway)
  --contract-file <path>       Capture/diff tools/list schema in this file
  --contract-source <name>     Stable label for the server in contract reports
  --update-contract            Replace the stored baseline after a comparison

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
    boolean: ['execute', 'allow-side-effects'],
    value: ['max-cases', 'protocol', 'case-mode'],
  });
  requireSafetyConsent(options);
  if (!options.commandArgs.length) throw new Error('A server command is required after `--`');
  const caseMode = options.caseMode ?? 'valid';
  if (!['valid', 'invalid', 'mixed'].includes(caseMode)) throw new Error('--case-mode must be valid, invalid, or mixed');
  const maxCases = parseMaxCases(options.maxCases);
  if (caseMode === 'mixed' && maxCases < 2) throw new Error('--max-cases must be at least 2 for --case-mode mixed');
  const { fuzzServer } = await import('./fuzz/client.js');
  const report = await fuzzServer({
    command: options.commandArgs[0],
    args: options.commandArgs.slice(1),
    protocol: protocolOption(options),
    maxCases,
    caseMode,
    execute: options.execute === true,
  });
  await printJson(report);
  if (report.tools.some((tool) => tool.results?.some((result) => result.outcome === 'protocol_error'))) process.exitCode = 1;
}

async function commandWorkflow(args) {
  const options = parseOptions(args, {
    boolean: ['execute', 'allow-side-effects'],
    value: ['file', 'protocol'],
  });
  requireSafetyConsent(options);
  if (!options.file) throw new Error('--file is required');
  if (!options.commandArgs.length) throw new Error('A server command is required after `--`');
  const workflowPath = resolve(options.file);
  const metadata = await stat(workflowPath);
  if (metadata.size > 1_048_576) throw new Error('Workflow file exceeds the 1 MiB safety limit');
  const workflow = JSON.parse(await readFile(workflowPath, 'utf8'));
  if (!Array.isArray(workflow.steps) || workflow.steps.length < 1 || workflow.steps.length > 500) {
    throw new Error('Workflow JSON must include between 1 and 500 steps');
  }
  const { runWorkflow } = await import('./fuzz/client.js');
  const report = await runWorkflow({
    command: options.commandArgs[0],
    args: options.commandArgs.slice(1),
    protocol: protocolOption(options),
    workflow,
    execute: options.execute === true,
  });
  await printJson(report);
  if (report.steps.some((step) => step.outcome === 'protocol_error' || step.outcome === 'unknown_tool' || step.outcome === 'skipped_invalid_arguments')) process.exitCode = 1;
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
      case 'snapshot': await commandSnapshot(args); break;
      case 'fuzz': await commandFuzz(args); break;
      case 'workflow': await commandWorkflow(args); break;
      case 'contract-diff': await commandContractDiff(args); break;
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
