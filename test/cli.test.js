import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createContract, writeContract } from '../src/contracts/contract.js';

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
  assert.match(help.stdout, /--oauth/);
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


test('contract-diff can fail CI when safety annotations change without a breaking schema change', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'mcp-inspector-contract-diff-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const baselinePath = join(dir, 'baseline.json');
  const currentPath = join(dir, 'current.json');
  const baseline = createContract([{
    name: 'read_file',
    annotations: { readOnlyHint: true, destructiveHint: false },
  }], 'fixture');
  const current = createContract([{
    name: 'read_file',
    annotations: { readOnlyHint: true, destructiveHint: false, title: 'Updated display label' },
  }], 'fixture');
  await Promise.all([writeContract(baselinePath, baseline), writeContract(currentPath, current)]);

  const reportOnly = runCli('contract-diff', '--baseline', baselinePath, '--current', currentPath);
  assert.equal(reportOnly.status, 0, reportOnly.stderr);
  assert.equal(JSON.parse(reportOnly.stdout).security_review_required, true);
  assert.equal(JSON.parse(reportOnly.stdout).breaking, false);

  const gated = runCli('contract-diff', '--baseline', baselinePath, '--current', currentPath, '--fail-on-security-review');
  assert.equal(gated.status, 1, gated.stderr);
  assert.equal(JSON.parse(gated.stdout).security_review_required, true);
});
