# Security model and deployment boundaries

## Scope

MCP Inspector is a local developer diagnostic tool and protocol observer. It is not an authentication gateway, tenant-isolation layer, policy engine, or guarantee that an MCP server is safe. Treat server metadata, tool schemas, error messages, URLs, and logs as untrusted operational data.

## Assets and trust boundaries

- MCP payloads: prompts, tool arguments, and tool results may contain credentials or personal data. The observer must not persist or export them by default.
- Endpoint configuration: the configured upstream URL and bearer token are trusted operator configuration. Do not embed credentials in URLs or pass secrets as command-line arguments.
- Dashboard browser boundary: the dashboard is intended for a local browser and binds to loopback. Host and Origin checks are defenses against DNS rebinding and cross-site request forgery, not a substitute for authentication on remote deployments.
- Trace and contract files: tool names, schema properties, endpoint paths, server identity and stack/error metadata may still be sensitive. Store exports with the same care as logs.

## Controls implemented in this repository

- HTTP and dashboard listeners bind to loopback by default. Non-loopback HTTP proxy binding requires an explicit opt-in and an external authenticated/TLS/rate-limiting gateway.
- The HTTP proxy rejects embedded URL credentials, validates browser Origin/Host policy, strips hop-by-hop and connection-nominated headers, and applies request/header timeouts.
- Upstream DNS lookups are checked at connection time to block private/reserved address resolution unless the exact hostname/IP is explicitly trusted; the checked IP is the IP the socket connects to, preventing a check-then-resolve DNS rebinding gap.
- Optional upstream headers use a bounded JSON map with header-name/value validation; hop-by-hop/Host/Content-Length overrides are rejected, and bearer-token configuration cannot conflict with a custom Authorization value.
- Dashboard APIs are read-only; arbitrary process execution is not exposed over HTTP. Report imports are processed in the browser rather than uploaded to the dashboard.
- Event recording uses an explicit field allowlist, bounds retained history, hashes string request identifiers, truncates untrusted strings, and removes common bearer/query-secret patterns.
- Fuzz and workflow tool execution are dry-run by default. Execution requires both --execute and --allow-side-effects; execute only against servers you own or are authorized to test.
- Compatibility probes are read-only: initialization and tools/list only. The probe does not invoke tools.

## Residual risks

- A malicious MCP server can return intentionally deceptive schemas, unbounded metadata, unexpected protocol behavior, or costly responses. Timeouts and size caps reduce but do not eliminate this risk.
- Redaction is defense in depth, not a proof that arbitrary application-specific secrets are absent. Do not enable payload capture or share trace exports without reviewing them.
- A bearer token configured for a private upstream must be protected as a secret. The CLI process environment and its host remain part of the trusted computing base.
- --allow-remote does not add authentication, TLS, authorization, or tenant isolation. Do not expose the proxy directly to the internet.
- SSRF risk remains if an operator deliberately points the CLI at untrusted/private endpoints. Use trusted URLs; do not turn user-submitted endpoint strings into unattended server-side jobs.

## Verification

Run npm run check, npm test, npm run test:browser, npm audit --audit-level=high, and review the generated SBOM. CI uses Node.js 22, 24, and 26 plus a Windows/Node 22 smoke lane. The browser E2E workflow installs Playwright and Chromium separately from the dependency-free unit-test path.

These checks are regression signals, not a substitute for independent penetration testing, a review of deployment infrastructure, or a formal security certification.
