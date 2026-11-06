import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ci = readFileSync(resolve(ROOT, '.github/workflows/ci.yml'), 'utf8').replace(/\r\n/g, '\n');
const browser = readFileSync(resolve(ROOT, '.github/workflows/browser-e2e.yml'), 'utf8').replace(/\r\n/g, '\n');
const codeql = readFileSync(resolve(ROOT, '.github/workflows/codeql.yml'), 'utf8').replace(/\r\n/g, '\n');

test('Browser E2E and CodeQL workflows are reusable without losing standalone triggers', () => {
  assert.match(browser, /^  workflow_call:\s*$/m);
  assert.match(browser, /^  pull_request:\s*$/m);
  assert.match(browser, /^    branches: \[main\]$/m);
  assert.match(codeql, /^  workflow_call:\s*$/m);
  assert.match(codeql, /^  pull_request:\s*$/m);
  assert.match(codeql, /^  schedule:\s*$/m);
});

test('CI invokes Browser E2E and CodeQL as reusable workflows', () => {
  assert.match(ci, /^  browser-e2e:\n    name: Browser E2E\n    uses: \.\/\.github\/workflows\/browser-e2e\.yml/m);
  assert.match(ci, /^  codeql:\n    name: CodeQL\n    uses: \.\/\.github\/workflows\/codeql\.yml/m);
});

test('the stable required aggregate fails closed on Browser E2E and CodeQL results', () => {
  const required = ci.slice(ci.indexOf('  required:\n'));
  assert.match(required, /needs: \[[^\]]*\bbrowser-e2e\b[^\]]*\bcodeql\b[^\]]*\]/);
  assert.match(required, /BROWSER_E2E_RESULT: \$\{\{ needs\.browser-e2e\.result \}\}/);
  assert.match(required, /CODEQL_RESULT: \$\{\{ needs\.codeql\.result \}\}/);
  assert.match(required, /test "\$BROWSER_E2E_RESULT" = success/);
  assert.match(required, /test "\$CODEQL_RESULT" = success/);
  assert.match(required, /set -euo pipefail/);
});
