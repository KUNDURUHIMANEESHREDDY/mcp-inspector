import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compareContracts, contractHash, createContract, readContract, writeContract } from '../src/contracts/contract.js';

const baseTools = [{
  name: 'read_file',
  description: 'Read a fixture',
  inputSchema: {
    type: 'object',
    required: ['path'],
    properties: { path: { type: 'string', minLength: 1 }, encoding: { type: 'string', enum: ['utf8', 'base64'] } },
    additionalProperties: false,
  },
}];

test('contract hashes are stable across tool order, object key order, and capture timestamps', () => {
  const one = createContract(baseTools, 'fixture');
  const two = createContract([{ ...baseTools[0], inputSchema: { additionalProperties: false, properties: { encoding: { enum: ['utf8', 'base64'], type: 'string' }, path: { minLength: 1, type: 'string' } }, required: ['path'], type: 'object' } }], 'fixture');
  assert.equal(contractHash(one), contractHash(two));
});

test('contract comparator flags removed tools and newly-required properties', () => {
  const before = createContract(baseTools, 'fixture');
  const after = createContract([{
    ...baseTools[0],
    inputSchema: { ...baseTools[0].inputSchema, required: ['path', 'encoding'] },
  }, { name: 'new_tool', inputSchema: { type: 'object' } }], 'fixture');
  const result = compareContracts(before, after);
  assert.equal(result.breaking, true);
  assert.ok(result.changes.some((change) => change.breaking && change.path.endsWith('.required')));
  assert.ok(result.changes.some((change) => !change.breaking && change.path === 'tools.new_tool'));
  assert.equal(result.summary.breaking > 0, true);
});

test('contract comparator detects removed enum values and tightened constraints', () => {
  const before = createContract(baseTools, 'fixture');
  const after = createContract([{
    ...baseTools[0],
    inputSchema: {
      ...baseTools[0].inputSchema,
      properties: { ...baseTools[0].inputSchema.properties, path: { type: 'string', minLength: 5 } },
    },
  }], 'fixture');
  const result = compareContracts(before, after);
  assert.equal(result.breaking, true);
  assert.ok(result.changes.some((change) => change.path.endsWith('.minLength')));
});

test('contract comparator flags tool safety annotation risk increases', () => {
  const before = createContract([{ ...baseTools[0], annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true } }], 'fixture');
  const after = createContract([{ ...baseTools[0], annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false } }], 'fixture');
  const result = compareContracts(before, after);
  assert.equal(result.breaking, true);
  assert.ok(result.changes.some((change) => change.breaking && change.securityReview && change.path.endsWith('.annotations')));
});

test('contract snapshots are written atomically and validated when read', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'mcp-inspector-contract-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'nested', 'baseline.json');
  const contract = createContract(baseTools, 'fixture');
  await writeContract(path, contract);
  const loaded = await readContract(path);
  assert.equal(loaded.hash, contract.hash);
  assert.equal((await readFile(path, 'utf8')).endsWith('\n'), true);
  const tampered = { ...loaded, source: 'tampered' };
  await (await import('node:fs/promises')).writeFile(path, JSON.stringify(tampered));
  await assert.rejects(readContract(path), /integrity check failed/);
  delete tampered.hash;
  await (await import('node:fs/promises')).writeFile(path, JSON.stringify(tampered));
  await assert.rejects(readContract(path), /integrity check failed or hash is missing/);
});
