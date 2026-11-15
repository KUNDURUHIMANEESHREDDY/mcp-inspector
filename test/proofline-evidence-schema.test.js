import test from 'node:test';
import assert from 'node:assert/strict';
import { validateProoflineEvidence } from '../src/proofline/evidence-schema.js';

const base = {
  schemaVersion: 1,
  recordType: 'verification',
  evidenceId: 'github-actions:run-842:unit-tests',
  issueKey: 'PAY-142',
  source: 'github-actions',
  sourceRunId: '842',
  observedAt: '2026-11-15T08:00:00Z',
  verifier: { name: 'proofline-github-actions-adapter', version: '0.1.0' },
};

test('accepts a provenance-bearing verification result', () => {
  const result = validateProoflineEvidence({
    ...base,
    criterionKey: 'unit-tests',
    outcome: 'PASS',
    artifact: {
      uri: 'https://ci.example.test/runs/842/artifacts/report',
      sha256: 'a'.repeat(64),
    },
  });
  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
});

test('accepts MCP operational observations as a distinct record type', () => {
  const result = validateProoflineEvidence({
    ...base,
    recordType: 'observation',
    evidenceId: 'mcp-inspector:session-12:rpc-9',
    source: 'mcp-inspector',
    eventName: 'mcp.rpc.response',
    observationStatus: 'success',
    toolName: 'run_tests',
    protocol: 'stdio',
    durationMs: 42,
    contractHash: 'b'.repeat(64),
  });
  assert.equal(result.valid, true);
});

test('does not allow MCP observations to satisfy verification criteria', () => {
  const result = validateProoflineEvidence({
    ...base,
    recordType: 'observation',
    evidenceId: 'mcp-inspector:session-12:rpc-9',
    source: 'mcp-inspector',
    eventName: 'mcp.rpc.response',
    observationStatus: 'success',
    criterionKey: 'unit-tests',
    outcome: 'PASS',
  });
  assert.equal(result.valid, false);
});

test('rejects verification records without an explicit criterion outcome', () => {
  const result = validateProoflineEvidence({
    ...base,
    criterionKey: 'unit-tests',
  });
  assert.equal(result.valid, false);
});

test('rejects unrecognized fields that could smuggle prompts or tool payloads', () => {
  for (const field of ['prompt', 'toolArguments', 'toolResult', 'rawRequest']) {
    const result = validateProoflineEvidence({
      ...base,
      criterionKey: 'unit-tests',
      outcome: 'PASS',
      [field]: 'must-not-be-accepted',
    });
    assert.equal(result.valid, false, `unexpectedly accepted ${field}`);
    assert.ok(result.errors.some((error) => error.keyword === 'additionalProperties'));
  }
});

test('rejects malformed timestamps, unsupported outcomes, and non-HTTPS artifacts', () => {
  const invalidTimestamp = validateProoflineEvidence({
    ...base,
    criterionKey: 'unit-tests',
    outcome: 'PASS',
    observedAt: 'yesterday',
  });
  assert.equal(invalidTimestamp.valid, false);

  const invalidOutcome = validateProoflineEvidence({
    ...base,
    criterionKey: 'unit-tests',
    outcome: 'SUCCESS',
  });
  assert.equal(invalidOutcome.valid, false);

  const invalidArtifact = validateProoflineEvidence({
    ...base,
    criterionKey: 'unit-tests',
    outcome: 'PASS',
    artifact: { uri: 'http://ci.example.test/report', sha256: 'c'.repeat(64) },
  });
  assert.equal(invalidArtifact.valid, false);
});
