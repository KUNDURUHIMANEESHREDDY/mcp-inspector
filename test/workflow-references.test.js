import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveWorkflowReferences } from '../src/workflows/references.js';

test('workflow references safely resolve JSON Pointer paths from earlier results', () => {
  const result = resolveWorkflowReferences({
    content: { $ref: 'read#/content/0/text' },
    escaped: { $ref: 'read#/structuredContent/a~1b' },
  }, new Map([['read', { content: [{ text: 'contents' }], structuredContent: { 'a/b': 'escaped-key' } }]]), new Map([['read', 0], ['write', 1]]), 1);
  assert.deepEqual(result.unresolved, []);
  assert.equal(result.referenceCount, 2);
  assert.deepEqual(result.value, { content: 'contents', escaped: 'escaped-key' });
});

test('workflow references reject forward references and prototype traversal', () => {
  const future = resolveWorkflowReferences({ content: { $ref: 'write#/content/0/text' } }, new Map(), new Map([['write', 2]]), 1);
  assert.equal(future.unresolved[0].reason, 'reference_must_target_an_earlier_step');
  const pollution = resolveWorkflowReferences({ content: { $ref: 'read#/constructor/prototype' } }, new Map([['read', {}]]));
  assert.equal(pollution.unresolved[0].reason, 'json_pointer_not_found');
});

test('workflow references report missing results instead of silently passing placeholders', () => {
  const result = resolveWorkflowReferences({ text: { $ref: 'read#/content/0/text' } }, new Map(), new Map([['read', 0], ['write', 1]]), 1);
  assert.equal(result.unresolved[0].reason, 'referenced_step_has_no_successful_result');
});
