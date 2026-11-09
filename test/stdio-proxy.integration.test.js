import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createStdioChildEnv } from '../src/proxy/stdio.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const supported = Number(process.versions.node.split('.')[0]) >= 22;
const upstreamCredentialNames = new Set([
  'MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN',
  'MCP_INSPECTOR_UPSTREAM_HEADERS',
]);

test('stdio child environment removes exact upstream credential keys on every platform', () => {
  const childEnv = createStdioChildEnv({
    PATH: '/safe/bin',
    MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN: 'must-not-leak',
    MCP_INSPECTOR_UPSTREAM_HEADERS: '{"authorization":"Bearer must-not-leak"}',
  }, 'linux');

  assert.deepEqual(childEnv, { PATH: '/safe/bin' });
});

test('stdio child environment removes differently cased upstream credential keys on Windows', () => {
  const childEnv = createStdioChildEnv({
    PATH: 'C:\\safe\\bin',
    mCp_InSpEcToR_UpStReAm_BeArEr_ToKeN: 'must-not-leak',
    McP_InSpEcToR_UpStReAm_HeAdErS: '{"authorization":"Bearer must-not-leak"}',
  }, 'win32');

  assert.deepEqual(childEnv, { PATH: 'C:\\safe\\bin' });
});

test('stdio child environment preserves case-sensitive names on POSIX', () => {
  const childEnv = createStdioChildEnv({
    PATH: '/safe/bin',
    mCp_InSpEcToR_UpStReAm_BeArEr_ToKeN: 'unrelated-posix-variable',
    McP_InSpEcToR_UpStReAm_HeAdErS: 'unrelated-posix-variable',
  }, 'linux');

  assert.equal(childEnv.mCp_InSpEcToR_UpStReAm_BeArEr_ToKeN, 'unrelated-posix-variable');
  assert.equal(childEnv.McP_InSpEcToR_UpStReAm_HeAdErS, 'unrelated-posix-variable');
});

test('stdio proxy forwards JSON-RPC bytes unchanged and keeps diagnostics off stdout', { skip: !supported }, async (t) => {
  const cli = resolve(root, 'src/cli.js');
  const echo = 'process.stdin.pipe(process.stdout)';
  const proxy = spawn(process.execPath, [cli, 'proxy', '--', process.execPath, '-e', echo], {
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: root,
    env: { ...process.env, MCP_INSPECTOR_LOG_LEVEL: 'error' },
  });
  t.after(() => { if (proxy.exitCode === null) proxy.kill('SIGKILL'); });
  const request = Buffer.from('{"jsonrpc":"2.0","id":11,"method":"ping"}\\n');
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
  const script = 'process.stdout.write(JSON.stringify({bearer:Object.hasOwn(process.env,"MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN"),headers:Object.hasOwn(process.env,"MCP_INSPECTOR_UPSTREAM_HEADERS")})+"\\n")';
  const proxy = spawn(process.execPath, [cli, 'proxy', '--', process.execPath, '-e', script], {
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: root,
    env: { ...process.env, MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN: 'must-not-leak', MCP_INSPECTOR_UPSTREAM_HEADERS: JSON.stringify({ authorization: 'Bearer must-not-leak' }), MCP_INSPECTOR_LOG_LEVEL: 'error' },
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
  assert.deepEqual(JSON.parse(output), { bearer: false, headers: false });
});

test('stdio proxy removes case-variant upstream credentials before launching a Windows MCP server', { skip: !supported || process.platform !== 'win32' }, async (t) => {
  const cli = resolve(root, 'src/cli.js');
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !upstreamCredentialNames.has(key.toUpperCase())),
  );
  env.mCp_InSpEcToR_UpStReAm_BeArEr_ToKeN = 'must-not-leak';
  env.McP_InSpEcToR_UpStReAm_HeAdErS = JSON.stringify({ authorization: 'Bearer must-not-leak' });
  env.MCP_INSPECTOR_LOG_LEVEL = 'error';

  const script = 'const names=Object.keys(process.env).map((key)=>key.toUpperCase()); process.stdout.write(JSON.stringify({bearer:names.includes("MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN"),headers:names.includes("MCP_INSPECTOR_UPSTREAM_HEADERS")})+"\\n")';
  const proxy = spawn(process.execPath, [cli, 'proxy', '--', process.execPath, '-e', script], {
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: root,
    env,
  });
  t.after(() => { if (proxy.exitCode === null) proxy.kill('SIGKILL'); });
  const output = await new Promise((resolvePromise, reject) => {
    const chunks = [];
    const timeout = setTimeout(() => reject(new Error('Windows stdio credential isolation check timed out')), 5000);
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

  assert.deepEqual(JSON.parse(output), { bearer: false, headers: false });
});
