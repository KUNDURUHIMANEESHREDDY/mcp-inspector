import assert from 'node:assert/strict';
import test from 'node:test';
import { findUnpinnedActionReferences } from '../scripts/workflow-action-pins.js';

test('accepts full immutable commit SHAs and version comments', () => {
  const source = '      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n';
  assert.deepEqual(findUnpinnedActionReferences(source, 'ci.yml'), []);
});

test('rejects mutable version tags in YAML list-form steps', () => {
  const issues = findUnpinnedActionReferences('      - uses: actions/checkout@v4\n', 'ci.yml');
  assert.equal(issues.length, 1);
  assert.deepEqual(issues[0], {
    file: 'ci.yml',
    line: 1,
    reference: 'actions/checkout@v4',
    reason: 'ref is not a full 40-character commit SHA',
  });
});

test('rejects action references without a ref', () => {
  const issues = findUnpinnedActionReferences('      - uses: actions/checkout\n', 'ci.yml');
  assert.equal(issues.length, 1);
  assert.match(issues[0].reason, /missing an immutable commit SHA/);
});

test('allows repository-local actions', () => {
  assert.deepEqual(findUnpinnedActionReferences('      - uses: ./.github/actions/test\n'), []);
});

test('reports every unpinned reference with its source line', () => {
  const source = [
    'name: test',
    'steps:',
    '  - uses: actions/checkout@v4',
    '  - uses: actions/setup-node@main',
  ].join('\n');
  const issues = findUnpinnedActionReferences(source, 'ci.yml');
  assert.deepEqual(issues.map(({ line, reference }) => ({ line, reference })), [
    { line: 3, reference: 'actions/checkout@v4' },
    { line: 4, reference: 'actions/setup-node@main' },
  ]);
});
