# Security model and deployment boundaries

## Scope

MCP Inspector is a local developer diagnostic tool and protocol observer. It is not a per-user identity provider, tenant-isolation layer, general policy engine, or guarantee that an MCP server is safe. Treat server metadata, tool schemas, error messages, URLs, and logs as untrusted operational data.

## Assets and trust boundaries

- MCP payloads: prompts, tool arguments, and tool results may contain credentials or personal data. The observer must not persist or export them by default.
- Endpoint configuration: the configured upstream URL, upstream bearer token, and remote-proxy bearer token are trusted operator configuration. Do not embed credentials in URLs or pass secrets as command-line arguments.
- Dashboard browser boundary: the dashboard is intended for a local browser and binds to loopback. Host and Origin checks are defenses against DNS rebinding and cross-site request forgery, not a substitute for authentication on remote deployments.
- Remote proxy clients: non-loopback HTTP proxy binds use one shared bearer credential. This authenticates possession of the configured secret; it does not identify individual users or authorize tenants/resources separately.
- Trace and contract files: tool names, schema properties, endpoint paths, server identity and stack/error metadata may still be sensitive. Store exports with the same care as logs.

## Controls implemented in the current remote-proxy candidate

- HTTP and dashboard listeners bind to loopback by default. The dashboard remains local-only.
- A non-loopback HTTP proxy bind requires all of: explicit `--allow-remote`, `MCP_INSPECTOR_PROXY_BEARER_TOKEN` with at least 32 characters, and a non-empty exact `MCP_INSPECTOR_ALLOWED_ORIGINS` allowlist.
- Every non-loopback proxy request must present `Authorization: Bearer <token>`. The token comparison uses a constant-time comparison after checking equal byte lengths. Unauthenticated requests are rejected before their bodies are drained or forwarded; repeated failures are throttled per peer using bounded in-memory state.
- The inbound proxy bearer credential is removed before forwarding. Upstream authentication is configured separately with `MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN` or `MCP_INSPECTOR_UPSTREAM_HEADERS`.
- The remote proxy validates Host and browser Origin policy, rejects ambiguous duplicate Host/Authorization headers and malformed request targets, strips hop-by-hop and connection-nominated headers, bounds request bodies, and applies request/header/upstream timeouts.
- Upstream DNS lookups are checked at connection time to block private/reserved address resolution unless the exact hostname/IP is explicitly trusted; the checked IP is the IP the socket connects to, preventing a check-then-resolve DNS rebinding gap.
- Optional upstream headers use a bounded JSON map with header-name/value validation; hop-by-hop/Host/Content-Length overrides are rejected, and bearer-token configuration cannot conflict with a custom Authorization value.
- The compatibility CLI can use the MCP SDK OAuth 2.1 authorization-code/PKCE flow for HTTP probes, validates loopback callback Host and state, and stores tokens only in memory for the current run. This OAuth client flow is not an OAuth reverse-proxy gateway and does not persist refresh tokens.
- Dashboard APIs are read-only; arbitrary process execution is not exposed over HTTP. Report imports are processed in the browser rather than uploaded to the dashboard.
- Event recording uses an explicit field allowlist, bounds retained history, hashes string request identifiers, truncates untrusted strings, and removes common bearer/query-secret patterns.
- Fuzz and workflow tool execution are dry-run by default. Execution requires both `--execute` and `--allow-side-effects`; execute only against servers you own or are authorized to test.
- Compatibility probes are read-only: initialization and tools/list only. The probe does not invoke tools.

## Deployment requirements and residual risks

- **TLS is not terminated by MCP Inspector.** Put a correctly configured TLS-terminating reverse proxy or gateway in front of any non-loopback listener. Do not send the shared bearer token over plaintext networks.
- **The remote bearer token is shared authentication, not per-user RBAC.** There are no individual identities, tenant/resource authorization boundaries, or per-user audit identities in this proxy candidate. Do not use it as a multi-tenant service boundary.
- **Failed-authentication throttling is not general request rate limiting.** Apply request/concurrency limits at the external gateway, including limits for authenticated clients.
- **Origin allowlisting is a browser boundary, not client authentication.** Non-browser clients can send arbitrary headers; the bearer token remains mandatory for non-loopback requests.
- The dashboard remains loopback-only. Do not expose it through a reverse proxy without a separate authenticated design review.
- A malicious MCP server can return intentionally deceptive schemas, unbounded metadata, unexpected protocol behavior, or costly responses. Timeouts and size caps reduce but do not eliminate this risk.
- Redaction is defense in depth, not a proof that arbitrary application-specific secrets are absent. Do not enable payload capture or share trace exports without reviewing them.
- A bearer token configured for a private upstream must be protected as a secret. The CLI process environment and its host remain part of the trusted computing base.
- SSRF risk remains if an operator deliberately points the CLI at untrusted/private endpoints. Use trusted URLs; do not turn user-submitted endpoint strings into unattended server-side jobs.

## Verification

Run `npm run check`, `npm test`, `npm run test:browser`, `npm audit --audit-level=high`, and review the generated SBOM. CI uses Node.js 22, 24, and 26 plus a Windows/Node 22 smoke lane. The browser E2E workflow installs Playwright and Chromium separately from the dependency-free unit-test path.

These checks are regression signals, not a substitute for independent penetration testing, a review of deployment infrastructure, or a formal security certification.
