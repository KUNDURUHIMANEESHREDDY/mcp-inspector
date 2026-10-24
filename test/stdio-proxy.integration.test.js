import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const supported = Number(process.versions.node.split('.')[0]) >= 22;

test('stdio proxy forwards JSON-RPC bytes unchanged and keeps diagnostics off stdout', { skip: !supported }, async (t) => {
  const cli = resolve(root, 'src/cli.js');
  const server = resolve(root, 'fixtures/echo-mcp-server.js');
  const proxy = spawn(process.execPath, [cli, 'proxy', '--', process.execPath, server], {
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: root,
    env: { ...process.env, MCP_INSPECTOR_LOG_LEVEL: 'error' },
  });
  t.after(() => { if (proxy.exitCode === null) proxy.kill('SIGKILL'); });
  const request = Buffer.from('{"jsonrpc":"2.0","id":11,"method":"ping"}\n');
  const response = await new Promise((resolvePromise, reject) => {
    const chunks = [];
    const timeout = setTimeout(() => reject(new Error('stdio proxy response timed out')), 5000);
    proxy.once('error', (error) => { clearTimeout(timeout); reject(error); });
    proxy.stdout.on('data', (chunk) => {
      chunks.push(chunk);
      const bytes = Buffer.concat(chunks);
      if (bytes.includes(0x0a)) {
        clearTimeout(timeout);
        resolvePromise(bytes.subarray(0, bytes.indexOf(0x0a) + 1));
      }
    });
    proxy.stderr.on('data', () => {});
    proxy.stdin.write(request);
  });
  assert.deepEqual(response, request);
  proxy.stdin.end();
});

test('stdio proxy does not leak its HTTP upstream bearer token to the launched MCP server', { skip: !supported }, async (t) => {
  const cli = resolve(root, 'src/cli.js');
  const script = 'process.stdout.write(JSON.stringify({present:Object.hasOwn(process.env,"MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN")})+"\\n")';
  const proxy = spawn(process.execPath, [cli, 'proxy', '--', process.execPath, '-e', script], {
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: root,
    env: { ...process.env, MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN: 'must-not-leak', MCP_INSPECTOR_LOG_LEVEL: 'error' },
  });
  t.after(() => { if (proxy.exitCode === null) proxy.kill('SIGKILL'); });
  const output = await new Promise((resolvePromise, reject) => {
    const chunks = [];
    const timeout = setTimeout(() => reject(new Error('stdio secret isolation check timed out')), 5000);
    proxy.once('error', (error) => { clearTimeout(timeout); reject(error); });
    proxy.stdout.on('data', (chunk) => {
      chunks.push(chunk);
      const bytes = Buffer.concat(chunks);
      if (bytes.includes(0x0a)) {
        clearTimeout(timeout);
        resolvePromise(bytes.subarray(0, bytes.indexOf(0x0a) + 1).toString('utf8'));
      }
    });
    proxy.stderr.on('data', () => {});
  });
  assert.deepEqual(JSON.parse(output), { present: false });
});
