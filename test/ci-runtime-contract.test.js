import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateMinimumRuntimeWorkflow } from '../scripts/ci-runtime-contract.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workflow = readFileSync(resolve(ROOT, '.github/workflows/ci.yml'), 'utf8').replace(/\r\n/g, '\n');

test('the declared minimum runtime job runs its required checks unconditionally', () => {
  assert.deepEqual(validateMinimumRuntimeWorkflow(workflow), []);
});

test('a step-level if cannot silently skip the minimum-runtime test suite', () => {
  const skipped = workflow.replace(
    '      - name: Unit and integration tests\n        run: npm test',
    '      - name: Unit and integration tests\n        if: ${{ false }}\n        run: npm test',
  );
  assert.notEqual(skipped, workflow);
  assert.match(validateMinimumRuntimeWorkflow(skipped).join('\n'), /step-level if condition/);
});

test('continue-on-error cannot turn a required runtime check into a warning', () => {
  const weakened = workflow.replace(
    '      - name: Dependency audit\n        run: npm audit --audit-level=high',
    '      - name: Dependency audit\n        continue-on-error: true\n        run: npm audit --audit-level=high',
  );
  assert.notEqual(weakened, workflow);
  assert.match(validateMinimumRuntimeWorkflow(weakened).join('\n'), /continue-on-error/);
});

test('the minimum runtime job cannot be made conditional or matrix-only', () => {
  const conditional = workflow.replace(
    '  minimum-runtime:\n    name: Minimum supported runtime / Node 22.15.0',
    '  minimum-runtime:\n    if: ${{ false }}\n    name: Minimum supported runtime / Node 22.15.0',
  );
  assert.match(validateMinimumRuntimeWorkflow(conditional).join('\n'), /job-level if condition/);
  const matrix = workflow.replace(
    '  minimum-runtime:\n    name: Minimum supported runtime / Node 22.15.0',
    '  minimum-runtime:\n    strategy:\n      matrix:\n        node: [22.15.0]\n    name: Minimum supported runtime / Node 22.15.0',
  );
  assert.match(validateMinimumRuntimeWorkflow(matrix).join('\n'), /matrix or strategy/);
});

test('job-level continue-on-error is rejected unless explicitly false', () => {
  const withJobSetting = (value) => workflow.replace(
    '  minimum-runtime:\n    name: Minimum supported runtime / Node 22.15.0',
    '  minimum-runtime:\n    continue-on-error: ' + value + '\n    name: Minimum supported runtime / Node 22.15.0',
  );
  assert.match(validateMinimumRuntimeWorkflow(withJobSetting('true')).join('\n'), /job-level continue-on-error/);
  assert.match(validateMinimumRuntimeWorkflow(withJobSetting('${{ false }}')).join('\n'), /job-level continue-on-error/);
  assert.deepEqual(validateMinimumRuntimeWorkflow(withJobSetting('false')), []);
  assert.deepEqual(validateMinimumRuntimeWorkflow(withJobSetting('false # explicit fail-closed value')), []);
});

test('CR-only and mixed line endings cannot hide a job-level failure override', () => {
  const weakened = workflow.replace(
    '  minimum-runtime:\n    name: Minimum supported runtime / Node 22.15.0',
    '  minimum-runtime:\n    continue-on-error: true\n    name: Minimum supported runtime / Node 22.15.0',
  ).replace(/\r?\n/g, '\r');
  assert.match(validateMinimumRuntimeWorkflow(weakened).join('\n'), /job-level continue-on-error/);
});
