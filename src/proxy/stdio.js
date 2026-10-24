import { spawn } from 'node:child_process';
import { MessageInspector } from '../protocol/inspector.js';
import { ContractRecorder } from '../contracts/contract.js';
import { log, logError } from '../observability/logger.js';

export function startStdioProxy(command, args = [], options = {}) {
  if (!command) throw new Error('A target command is required after `--`');
  const childEnv = { ...process.env };
  // This secret authenticates only the HTTP upstream; it must never be inherited
  // by an unrelated stdio MCP server launched by the proxy.
  delete childEnv.MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN;
  const child = spawn(command, args, {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: childEnv,
    windowsHide: true,
    shell: false,
  });
  const maxFrameBytes = options.maxFrameBytes;
  const pendingStore = new Map();
  const contractRecorder = new ContractRecorder({ path: options.contractFile, source: options.contractSource || command, update: options.updateContract });
  const clientToServer = new MessageInspector({
    direction: 'client_to_server',
    transport: 'stdio',
    contractFile: options.contractFile,
    contractSource: options.contractSource || command,
    updateContract: options.updateContract,
    maxFrameBytes,
    pendingStore,
    contractRecorder,
  });
  const serverToClient = new MessageInspector({
    direction: 'server_to_client',
    transport: 'stdio',
    contractFile: options.contractFile,
    contractSource: options.contractSource || command,
    updateContract: options.updateContract,
    maxFrameBytes,
    pendingStore,
    contractRecorder,
  });

  let closing = false;
  let exitHandled = false;
  let killTimer;
  let resolveDone;
  const done = new Promise((resolve) => { resolveDone = resolve; });
  const onStdinData = (chunk) => {
    // Forward first; inspect the same immutable chunk afterward to keep CPU work
    // off the most latency-sensitive part of the path.
    if (!child.stdin.write(chunk)) process.stdin.pause();
    clientToServer.push(chunk);
  };
  process.stdin.on('data', onStdinData);
  child.stdin.on('drain', () => process.stdin.resume());
  // A server that exits while input is still arriving can close stdin with EPIPE.
  // Consume that stream error so it cannot crash the host MCP client process.
  child.stdin.on('error', (error) => {
    logError('proxy.upstream_stdin_error', error, { transport: 'stdio' });
    process.stdin.pause();
  });
  process.stdin.on('end', () => child.stdin.end());
  process.stdin.on('error', (error) => {
    if (!closing) logError('proxy.client_stdin_error', error, { transport: 'stdio' });
    child.stdin.destroy();
  });

  child.stdout.on('data', (chunk) => {
    if (!process.stdout.write(chunk)) child.stdout.pause();
    serverToClient.push(chunk);
  });
  process.stdout.on('drain', () => child.stdout.resume());
  child.stdout.on('end', () => serverToClient.end());
  child.stderr.on('data', (chunk) => {
    if (!process.stderr.write(chunk)) child.stderr.pause();
  });
  process.stderr.on('drain', () => child.stderr.resume());

  const cleanup = () => {
    if (closing) return;
    closing = true;
    process.stdin.off('data', onStdinData);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    killTimer = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }, 2_000);
    killTimer.unref();
  };
  process.once('SIGINT', cleanup);
  process.once('SIGTERM', cleanup);

  child.once('error', (error) => {
    logError('proxy.child_spawn_error', error, { command, transport: 'stdio' });
    process.exitCode = 127;
    cleanup();
  });
  child.once('close', (code, signal) => {
    exitHandled = true;
    if (killTimer) clearTimeout(killTimer);
    clientToServer.end();
    serverToClient.end();
    clientToServer.flushPending?.('transport_closed');
    serverToClient.flushPending?.('transport_closed');
    closing = true;
    process.stdin.off('data', onStdinData);
    process.removeListener('SIGINT', cleanup);
    process.removeListener('SIGTERM', cleanup);
    if (signal && !process.exitCode) process.exitCode = signal === 'SIGINT' ? 130 : 143;
    else if (typeof code === 'number') process.exitCode = code;
    log('info', 'proxy.child_exit', { transport: 'stdio', exit_code: code, signal: signal || undefined });
    resolveDone({ code, signal });
  });

  log('info', 'proxy.started', { transport: 'stdio', command, args_count: args.length });
  return {
    child,
    done,
    close: () => {
      cleanup();
      if (!exitHandled) log('debug', 'proxy.close_requested', { transport: 'stdio' });
    },
  };
}
