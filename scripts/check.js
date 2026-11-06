#!/usr/bin/env node
import { readdir, readFile, stat } from 'node:fs/promises';
import { resolve, join, relative } from 'node:path';
import { spawnSync } from 'node:child_process';
import { findUnpinnedActionReferences } from './workflow-action-pins.js';

const root = resolve(import.meta.dirname, '..');
const scanRoots = ['src', 'test', 'bench', 'scripts', 'fixtures'];
const jsFiles = [];
async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await walk(path);
    else if (entry.isFile() && path.endsWith('.js')) jsFiles.push(path);
  }
}

for (const directory of scanRoots) await walk(join(root, directory));
jsFiles.sort();
let failed = false;
for (const file of jsFiles) {
  const check = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (check.status !== 0) {
    failed = true;
    process.stderr.write(check.stderr || `Syntax check failed: ${relative(root, file)}\n`);
  }
}

for (const file of ['package.json', 'workflow.example.json']) {
  try { JSON.parse(await readFile(join(root, file), 'utf8')); }
  catch (error) {
    failed = true;
    process.stderr.write(`Invalid JSON ${file}: ${error?.message ?? 'parse error'}\n`);
  }
}
const packageJson = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
if (!String(packageJson.engines?.node ?? '').includes('22')) {
  failed = true;
  process.stderr.write('package.json must declare a tested Node.js engine floor.\n');
}
if ((await stat(join(root, 'README.md'))).size < 1000) {
  failed = true;
  process.stderr.write('README.md is missing required project documentation.\n');
}

const workflowRoot = join(root, '.github', 'workflows');
const workflowFiles = [];
async function walkWorkflows(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await walkWorkflows(path);
    else if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) workflowFiles.push(path);
  }
}
await walkWorkflows(workflowRoot);
workflowFiles.sort();
for (const file of workflowFiles) {
  const source = await readFile(file, 'utf8');
  for (const issue of findUnpinnedActionReferences(source, relative(root, file))) {
    failed = true;
    process.stderr.write(
      `Unpinned workflow action at ${issue.file}:${issue.line}: ${issue.reference} (${issue.reason})\n`,
    );
  }
}

if (failed) {
  process.stderr.write('Static checks failed.\n');
  process.exitCode = 1;
} else {
  process.stdout.write(
    `Static checks passed for ${jsFiles.length} JavaScript files, JSON manifests, README, and ${workflowFiles.length} workflow files with immutable action refs.\n`,
  );
}
