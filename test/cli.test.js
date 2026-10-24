import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cli = resolve(root, 'src/cli.js');

function runCli(...args) {
  return spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8',
    timeout: 5_000,
    env: { ...process.env, MCP_INSPECTOR_LOG_LEVEL: 'error' },
  });
}

test('CLI help and version work without initializing optional proxy integrations', () => {
  const help = runCli('help');
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /Protocol-level observability/);
  assert.match(help.stdout, /mcp-inspector dashboard/);
  assert.match(help.stdout, /mcp-inspector compat/);
  const version = runCli('version');
  assert.equal(version.status, 0, version.stderr);
  assert.match(version.stdout.trim(), /^0\.1\.0$/);
});

test('CLI rejects unknown proxy options and malformed safety flags clearly', () => {
  const unknown = runCli('proxy', '--not-an-option');
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /Unknown option: --not-an-option/);
  const missingSeparator = runCli('fuzz', '--allow-side-effects');
  assert.equal(missingSeparator.status, 2);
  assert.match(missingSeparator.stderr, /requires --execute/);
  const invalidMixed = runCli('fuzz', '--case-mode', 'mixed', '--max-cases', '1', '--', process.execPath, 'server.js');
  assert.equal(invalidMixed.status, 2);
  assert.match(invalidMixed.stderr, /at least 2 for --case-mode mixed/);
  const invalidMax = runCli('fuzz', '--max-cases', 'not-a-number', '--', process.execPath, 'server.js');
  assert.equal(invalidMax.status, 2);
  assert.match(invalidMax.stderr, /integer from 1 to 500/);
  const invalidTransport = runCli('compat', '--transport', 'tcp');
  assert.equal(invalidTransport.status, 2);
  assert.match(invalidTransport.stderr, /--transport must be stdio, http, or both/);
});
