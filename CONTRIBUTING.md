# Contributing

## Development prerequisites

- Node.js 24 LTS or Node.js 26
- npm 10+
- Git

## Workflow

1. Create a focused branch.
2. Install dependencies with `npm install` (commit the lockfile when changed).
3. Run `npm run check`, `npm test`, and `npm audit --audit-level=high`.
4. Keep stdout protocol-clean in stdio proxy mode; diagnostics go to stderr.
5. Never log tool arguments, tool results, authorization headers, or prompt content.
6. Keep tool execution disabled unless the operator explicitly provides both safety flags.
7. Include a reproducible test and actual verification evidence for protocol or security changes.

## Pull requests

Use the pull request template. Changes to protocol semantics should identify the MCP revision and both modern/legacy compatibility expectations. Changes to dependencies should include audit results and an updated lockfile.
