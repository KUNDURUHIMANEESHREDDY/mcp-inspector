# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected security vulnerability. Use GitHub's private vulnerability reporting feature when enabled for the repository, or contact the maintainers privately through their GitHub profile.

Include affected versions, reproduction steps, expected impact, and a suggested mitigation when possible. Do not include real customer data, access tokens, credentials, prompt content, or production tool results in the report.

## Security boundaries

- Fuzzing is dry-run by default. Execution requires explicit `--execute --allow-side-effects` consent.
- Only fuzz systems for which you have authorization. Prefer a disposable test server and fixture data.
- HTTP proxy binds to loopback by default. The `--allow-remote` flag does not add authentication, TLS, or rate limiting.
- Tool arguments, results, prompts, and authorization values must not be added to logs or tracing attributes.
- Treat contract snapshots, tool names, error metadata, and OpenTelemetry data as potentially sensitive operational data.
- The proxy is not a substitute for an authenticated production gateway, network policy, or security review.

## Supported versions

Until a stable 1.x release exists, security fixes target the latest published `0.x` version on the default branch. Update dependencies and rerun the CI workflow before production use.
