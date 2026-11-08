/**
 * Validate the small, security-critical subset of GitHub Actions YAML that
 * establishes the declared minimum Node.js runtime. Unknown or conditional
 * shapes fail closed instead of being accepted by loose text matching.
 */
function jobBlock(source, name) {
  const lines = source.replace(/\r\n/g, '\n').split('\n');
  const start = lines.findIndex((line) => line === '  ' + name + ':');
  if (start < 0) return null;
  let end = start + 1;
  while (end < lines.length && !/^ {2}[A-Za-z0-9_-]+:\s*(?:#.*)?$/.test(lines[end])) end += 1;
  return lines.slice(start, end);
}

function stepBlocks(jobLines) {
  const start = jobLines.findIndex((line) => /^    steps:\s*(?:#.*)?$/.test(line));
  if (start < 0) return { steps: [], error: 'minimum-runtime job has no steps list.' };
  const steps = [];
  const errors = [];
  let current = null;

  for (let index = start + 1; index < jobLines.length; index += 1) {
    const line = jobLines[index];
    if (/^      -(?:\s|$)/.test(line)) {
      if (current) steps.push(current);
      current = [line];
      continue;
    }
    if (/^    [A-Za-z0-9_-]+\s*:/.test(line) || /^  [A-Za-z0-9_-]+\s*:/.test(line)) {
      if (current) steps.push(current);
      current = null;
      break;
    }
    if (current) current.push(line);
    else if (line.trim()) errors.push('Unsupported YAML structure in minimum-runtime steps.');
  }
  if (current) steps.push(current);
  return { steps, error: errors.join(' ') || null };
}

function property(step, key) {
  const inline = step.find((line) => line.startsWith('      - ' + key + ':'));
  const nested = step.find((line) => line.startsWith('        ' + key + ':'));
  const match = inline ?? nested;
  if (!match) return null;
  return match.slice(match.indexOf(':') + 1).trim();
}

function stepIsConditional(step) {
  return step.some((line) => /^      -\s*if\s*:|^        if\s*:/.test(line));
}

function stepAllowsFailure(step) {
  const value = property(step, 'continue-on-error');
  return value !== null && value !== 'false';
}

function matchingSteps(steps, predicate) {
  return steps.filter(predicate);
}

/**
 * Return actionable errors when the Linux minimum-runtime job can be skipped,
 * conditionally bypassed, or no longer executes the required checks.
 */
export function validateMinimumRuntimeWorkflow(source) {
  const errors = [];
  const job = jobBlock(source, 'minimum-runtime');
  if (!job) return ['CI must define a minimum-runtime job.'];

  const jobText = job.join('\n');
  if (/^    if\s*:/m.test(jobText)) errors.push('minimum-runtime job must not have a job-level if condition.');
  if (/^    strategy\s*:/m.test(jobText)) errors.push('minimum-runtime job must not use a matrix or strategy.');
  if (!/^    runs-on:\s*ubuntu-latest\s*$/m.test(jobText)) {
    errors.push('minimum-runtime job must run on ubuntu-latest.');
  }

  const parsed = stepBlocks(job);
  if (parsed.error) errors.push(parsed.error);
  const steps = parsed.steps;
  if (steps.length === 0) errors.push('minimum-runtime job must contain executable steps.');

  for (const step of steps) {
    if (stepIsConditional(step)) errors.push('minimum-runtime steps must not have a step-level if condition.');
    if (stepAllowsFailure(step)) errors.push('minimum-runtime steps must not set continue-on-error.');
  }

  const requiredRunCommands = [
    'npm ci --no-audit --no-fund',
    'npm run check',
    'npm test',
    'npm run test:compat',
    'npm audit --audit-level=high',
  ];
  const checkout = matchingSteps(steps, (step) => (property(step, 'uses') ?? '').startsWith('actions/checkout@'));
  if (checkout.length !== 1) errors.push('minimum-runtime job must have exactly one checkout step.');
  const setup = matchingSteps(steps, (step) => {
    const uses = property(step, 'uses') ?? '';
    const version = step.find((line) => /^          node-version:\s*/.test(line));
    return uses.startsWith('actions/setup-node@') && version?.trim() === "node-version: '22.15.0'";
  });
  if (setup.length !== 1) errors.push('minimum-runtime job must set up Node.js 22.15.0 exactly once.');

  for (const command of requiredRunCommands) {
    const matches = matchingSteps(steps, (step) => property(step, 'run') === command);
    if (matches.length !== 1) errors.push('minimum-runtime job must execute exactly once: ' + command + '.');
  }
  return errors;
}
