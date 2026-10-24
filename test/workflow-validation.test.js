import test from 'node:test';
import assert from 'node:assert/strict';
import { validateWorkflowInput } from '../src/workflows/validate.js';

const oneStep = () => ({ steps: [{ id: 'first', tool: 'echo', arguments: { message: 'ok' } }] });

test('workflow validation accepts bounded, JSON-safe plans', () => {
  assert.doesNotThrow(() => validateWorkflowInput(oneStep()));
});

test('workflow validation rejects empty, oversized, and excessive-step plans', () => {
  assert.throws(() => validateWorkflowInput({ steps: [] }), /between 1 and 500 steps/);
  assert.throws(() => validateWorkflowInput({ steps: Array.from({ length: 501 }, () => ({ tool: 'echo', arguments: {} })) }), /between 1 and 500 steps/);
  const oversized = oneStep();
  oversized.steps[0].arguments.message = 'x'.repeat(1_048_576);
  assert.throws(() => validateWorkflowInput(oversized), /must not exceed 1 MiB/);
});

test('workflow validation rejects duplicate IDs, invalid arguments, and invalid names', () => {
  const duplicate = { steps: [
    { id: 'same', tool: 'echo', arguments: {} },
    { id: 'same', tool: 'echo', arguments: {} },
  ] };
  assert.throws(() => validateWorkflowInput(duplicate), /Duplicate workflow step id/);
  assert.throws(() => validateWorkflowInput({ steps: [{ tool: 'echo', arguments: [] }] }), /Invalid workflow step/);
  assert.throws(() => validateWorkflowInput({ name: 'x'.repeat(257), steps: oneStep().steps }), /Workflow name/);
  const cyclic = oneStep();
  cyclic.steps[0].arguments.self = cyclic;
  assert.throws(() => validateWorkflowInput(cyclic), /JSON-serializable/);
});
