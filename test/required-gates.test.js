import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ci = readFileSync(resolve(ROOT, '.github/workflows/ci.yml'), 'utf8').replace(/\r\n/g, '\n');
const browser = readFileSync(resolve(ROOT, '.github/workflows/browser-e2e.yml'), 'utf8').replace(/\r\n/g, '\n');
const codeql = readFileSync(resolve(ROOT, '.github/workflows/codeql.yml'), 'utf8').replace(/\r\n/g, '\n');
const release = readFileSync(resolve(ROOT, '.github/workflows/release.yml'), 'utf8').replace(/\r\n/g, '\n');

test('Browser E2E and CodeQL workflows are reusable without losing standalone triggers', () => {
  assert.match(browser, /^  workflow_call:\s*$/m);
  assert.match(browser, /^  workflow_dispatch:\s*$/m);
  assert.doesNotMatch(browser, /^  pull_request:/m);
  assert.doesNotMatch(browser, /^  push:/m);
  assert.match(codeql, /^  workflow_call:\s*$/m);
  assert.match(codeql, /^  schedule:\s*$/m);
  assert.match(codeql, /^  workflow_dispatch:\s*$/m);
  assert.doesNotMatch(codeql, /^  pull_request:/m);
  assert.doesNotMatch(codeql, /^  push:/m);
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


test('release packaging is blocked until reusable Browser E2E and CodeQL workflows pass', () => {
  assert.match(release, /^  browser-e2e:\n    name: Required browser E2E\n    uses: \.\/\.github\/workflows\/browser-e2e\.yml/m);
  assert.match(release, /^  codeql:\n    name: Required CodeQL\n    uses: \.\/\.github\/workflows\/codeql\.yml/m);
  assert.match(release, /^  package:\n    name: Verify and package release assets\n    needs: \[browser-e2e, codeql\]/m);
  assert.match(release, /^  publish:\n    name: Publish GitHub release\n    if: startsWith\(github\.ref, 'refs\/tags\/'\)\n    needs: \[package\]/m);
  assert.match(release, /security-events: write/);
});
