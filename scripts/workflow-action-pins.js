export function findUnpinnedActionReferences(source, file = '<workflow>') {
  const issues = [];
  const lines = String(source).split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    // GitHub Actions step syntax commonly prefixes `uses:` with a YAML list dash.
    const match = /^\s*(?:-\s*)?uses:\s*([^\s#]+)/.exec(lines[index]);
    if (!match) continue;
    const reference = match[1];
    if (reference.startsWith('./')) continue;
    const separator = reference.lastIndexOf('@');
    if (separator <= 0) {
      issues.push({ file, line: index + 1, reference, reason: 'missing an immutable commit SHA' });
      continue;
    }
    const sha = reference.slice(separator + 1);
    if (!/^[a-f0-9]{40}$/i.test(sha)) {
      issues.push({ file, line: index + 1, reference, reason: 'ref is not a full 40-character commit SHA' });
    }
  }
  return issues;
}
