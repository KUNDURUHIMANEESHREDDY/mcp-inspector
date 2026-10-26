# MCP Inspector

**Protocol-level observability, contract drift detection, and schema-driven fuzzing for Model Context Protocol (MCP) systems.**

MCP Inspector is a local-first CLI with a built-in web dashboard. It sits between an MCP client and server or proxies Streamable HTTP traffic. It forwards original transport bytes and performs bounded, side-channel inspection so teams can investigate latency, JSON-RPC failures, tool-schema drift, and edge-case tool handling without logging prompts or tool arguments by default.

> **Release status:** early-stage software. Unit and local proxy tests are available, and an official-SDK interoperability suite is included for CI. Run the full dependency-backed suite, inspect the SBOM and audit findings, and benchmark your own servers before production use. Remote HTTP binding requires a shared client bearer token and an exact Origin allowlist, but still needs a TLS-terminating, rate-limiting gateway for internet exposure.

## Windows quick start

1. Install Node.js 22 or newer, Git, and npm.
2. Extract this repository ZIP.
3. Double-click `RUN_LOCAL_CHECKS.bat` first. It installs dependencies and runs static checks, tests, the dependency audit, and benchmarks. The window stays open on success or failure.
4. Double-click `RUN_DASHBOARD.bat` to connect to a Streamable HTTP MCP server (default `http://127.0.0.1:3000`). Enter the actual upstream URL, then open `http://127.0.0.1:9911`; configure your MCP client to use the proxy at `http://127.0.0.1:9900` with the upstream's MCP path (commonly `/mcp`).
4. After local verification succeeds, run `gh auth login` in PowerShell and double-click `PUSH_TO_GITHUB.bat` to create/push the repository.

If an older extracted copy reports an OpenTelemetry `ERESOLVE` error, run `FIX_OTEL_DEPENDENCY.bat` once; it pins the API package to a version accepted by the selected SDK, then retries dependency installation. If a script stops for another reason, copy the error text from the terminal; a failed check intentionally prevents publishing.

## What it does

- **Transparent stdio proxy:** launches a target command without a shell, forwards standard input/output bytes unchanged, keeps diagnostics on stderr, and observes newline-framed JSON-RPC messages on a bounded side channel.
- **Streamable HTTP/SSE reverse proxy:** forwards HTTP bodies without buffering the whole exchange, inspects JSON/SSE events within configured memory limits, strips hop-by-hop headers (including connection-nominated headers), and binds to loopback by default.
- **Protocol inspection:** correlates requests and responses using transport/session scope and JSON-RPC IDs; records method, tool name, bytes, duration, timeout, and protocol error metadata without recording arguments or results.
- **OpenTelemetry traces:** emits MCP/JSON-RPC spans through the OpenTelemetry API. Configure an OTLP/HTTP endpoint to export traces. Valid W3C `traceparent` values can parent spans; only well-formed hexadecimal or UUID trace IDs are accepted as correlation attributes.
- **Contract snapshots and drift detection:** captures `tools/list` responses, writes atomic JSON baselines, hashes normalized tool schemas, and reports likely breaking changes.
- **Schema-driven fuzzing:** derives schema-valid boundary cases plus intentionally schema-invalid cases. Dry-run is the default. Invoking real tools requires both `--execute` and `--allow-side-effects`.
- **Stateful workflow replay:** run ordered tool-call scenarios. Successful earlier responses can feed later arguments using JSON Pointer references; unresolved and forward references are rejected.

## Requirements

- Node.js **22 or newer** and npm 10 or newer.
- Git is only needed for contributing.
- An OTLP/HTTP trace collector is optional.

Install the reviewed dependency graph from a clone or extracted source directory:

```bash
npm ci
npm run check
npm test
```

Use `npm install` only when intentionally changing dependencies; review the resulting manifest and lockfile diff before committing.

The OpenTelemetry SDK/exporter versions are pinned together at `0.223.0`; `@opentelemetry/api` is pinned to `1.9.1` because SDK `0.223.0` declares a peer range below `1.10.0`. Do not use `--force` or `--legacy-peer-deps` to bypass this compatibility check. The SDK-backed interoperability tests use the official MCP TypeScript SDK v2 and a small local fixture server. If dependency installation fails, those tests cannot execute; do not treat skipped tests as passing evidence. The repository includes `package-lock.json`. CI uses `npm ci` in the Node 22/24/26 matrix, the Windows Node 22 lane, and the browser E2E workflow so verification uses the reviewed dependency graph. The stable `required` job fails unless the full runtime matrix and Windows smoke lane pass. Keep the lockfile in sync when dependencies change; review the manifest/lockfile diff and audit output before proposing dependency updates.

## Quick start

### 1. Inspect an MCP server without changing your client

Wrap the server command normally used by your MCP client:

```bash
mcp-inspector proxy -- npx -y @modelcontextprotocol/server-filesystem ./workspace
```

In your MCP client configuration, run the same command as the server executable, replacing it with `node /absolute/path/to/mcp-inspector/src/cli.js proxy -- npx -y @modelcontextprotocol/server-filesystem ./workspace` (quote arguments as required by your client). Because stdout is the MCP protocol channel, logs and diagnostics go to stderr.

The proxy does not know what the wrapped server's original executable or arguments should be. Use your actual configuration and avoid copying secrets into command lines or process listings.

### 2. Proxy a Streamable HTTP endpoint

```bash
mcp-inspector proxy --upstream http://127.0.0.1:3000 --listen 127.0.0.1:9900
```

Point the MCP client at `http://127.0.0.1:9900/mcp` if your upstream endpoint is `/mcp`. The proxy preserves the incoming path and query string relative to the configured upstream origin. Use an upstream URL without username/password credentials.

For a private upstream, set `MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN` in the process environment. Credentials are not read from the upstream URL. The token is sent only over HTTPS for non-loopback upstream hosts.

**Do not add `--allow-remote` unless you have placed a TLS-terminating, rate-limiting gateway in front of the proxy.** Non-loopback binding now also requires `MCP_INSPECTOR_PROXY_BEARER_TOKEN` (at least 32 characters) and a non-empty `MCP_INSPECTOR_ALLOWED_ORIGINS` list. The shared bearer token authenticates clients to this proxy but is not per-user authorization and does not provide TLS or rate limits.

### 3. Capture a tool contract

```bash
mcp-inspector snapshot --output .mcp-inspector/contracts/filesystem.json --protocol auto -- npx -y @modelcontextprotocol/server-filesystem ./workspace
```

Capture again after a server update and compare:

```bash
mcp-inspector contract-diff \
  --baseline .mcp-inspector/contracts/filesystem-before.json \
  --current .mcp-inspector/contracts/filesystem-after.json
```

Exit code `1` indicates that the report contains a potentially breaking change. Keep baselines under version control only if the tool inventory and schema metadata are appropriate for your repository.

### 4. Generate fuzz candidates

Safe default: generate and report candidates without making any tool call.

```bash
mcp-inspector fuzz --max-cases 50 --case-mode mixed --protocol auto -- npx -y @modelcontextprotocol/server-filesystem ./workspace
```

Case modes:

- `valid`: schema-valid baseline and boundary candidates (default).
- `invalid`: candidates intended to violate the advertised input schema.
- `mixed`: a bounded mixture of both.

To execute cases against a **disposable, authorized test server**:

```bash
mcp-inspector fuzz --max-cases 30 --case-mode mixed --execute --allow-side-effects --protocol auto -- node ./fixtures/sdk-mcp-server.js
```

Those two flags are intentionally required together. Even schema-valid arguments may cause side effects because the server controls tool semantics. Start with dry-run and inspect the candidate labels before enabling execution.

### Protocol compatibility suite

Run read-only initialize + tools/list probes against each selected transport and protocol mode. It never invokes a tool.

```bash
# stdio fixture
node ./src/cli.js compat --transport stdio -- node ./fixtures/sdk-mcp-server.js

# Streamable HTTP
node ./src/cli.js compat --transport http --url http://127.0.0.1:3000/mcp

# both transports
node ./src/cli.js compat --transport both --url http://127.0.0.1:3000/mcp -- node ./fixtures/sdk-mcp-server.js
```

The JSON report contains one pass/fail result per transport/protocol combination, negotiated protocol era, elapsed time, tool count, and normalized contract hash. Exit code 1 means at least one probe failed. URL credentials are rejected. For protected HTTP endpoints, configure `MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN` or `MCP_INSPECTOR_UPSTREAM_HEADERS` for static credentials. `--oauth` invokes the MCP SDK's OAuth authorization-code/PKCE flow, prints the authorization URL to stderr, checks the loopback callback's Host and state, and holds tokens in memory only for the current process. OAuth requires HTTPS off loopback. Results reflect only the target endpoint actually tested; this is not blanket certification of third-party servers.

### 5. Replay a stateful workflow

`workflow.example.json` demonstrates a workflow that calls the local SDK fixture's `echo` tool and feeds its structured output into `concat`. A reference can read a JSON Pointer from a prior successful tool result:

```json
{
  "name": "echo-then-concat",
  "steps": [
    { "id": "source", "tool": "echo", "arguments": { "message": "stateful-workflow" } },
    {
      "id": "combine",
      "tool": "concat",
      "arguments": {
        "left": { "$ref": "source#/structuredContent/echo" },
        "right": "-verified"
      }
    }
  ]
}
```

Run the workflow in dry-run mode:

```bash
mcp-inspector workflow --file workflow.example.json --protocol auto -- node ./fixtures/sdk-mcp-server.js
```

To execute this disposable, side-effect-free fixture's workflow, add `--execute --allow-side-effects` before the `--` separator. References resolve only during execution when an earlier step returned successfully. In dry-run mode, unresolved dependencies are reported rather than replaced with made-up values. JSON Pointer traversal blocks prototype-related keys.

## Local web dashboard

The dashboard is served by the same inspector process that observes traffic. It uses the Node.js built-in HTTP server and Server-Sent Events, with no extra frontend dependencies or build step. It is read-only and always binds to loopback.

For an HTTP-based MCP server:

```bash
node ./src/cli.js dashboard --upstream http://127.0.0.1:3000 --proxy-listen 127.0.0.1:9900 --dashboard-listen 127.0.0.1:9911
```

Point the MCP client at the proxy endpoint (for example, `http://127.0.0.1:9900/mcp`) and open `http://127.0.0.1:9911` in a browser. The dashboard shows live request/response metadata, measured response durations, recent protocol warnings, and contract events emitted by that proxy process.

For a stdio-based server, use the dashboard mode as the command in your MCP client's server configuration:

```bash
node /absolute/path/to/mcp-inspector/src/cli.js dashboard --stdio -- <server-command> [args...]
```

Open `http://127.0.0.1:9911` while that client-launched process is running. For stdio, stdout remains the MCP protocol channel; dashboard diagnostics stay on stderr. The dashboard binds to loopback only, rejects non-local browser Origins and Host headers, serves a strict Content Security Policy, and offers no API for starting arbitrary commands. Event retention is bounded and whitelists operational fields; tool arguments, prompts and results are not captured. Exported session data contains sanitized metadata only.

Use **Contracts** to compare two existing contract JSON files locally in the browser. Use **Fuzz reports** to load the JSON produced by `mcp-inspector fuzz`; the files are parsed in the browser and are not uploaded to the inspector server. These views review existing snapshots and reports rather than launching fuzz jobs from the browser.

## Observability and configuration

Outbound HTTP requests enforce DNS/address checks against private and special-use IP ranges. To intentionally connect to a trusted private upstream, list its exact hostname or IP in `MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS`. This allowlist has no wildcard support. Optional upstream headers can be set with `MCP_INSPECTOR_UPSTREAM_HEADERS` as a JSON object, or configure `MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN`; do not set both for Authorization.

The dashboard summary includes retained-history p50/p95/p99 latency, 60-second request throughput, response error rate, timeout count, schema-drift events, and repeated-failure groups. Metrics are bounded by the 2,000-event retention buffer and are diagnostic indicators, not a durable time-series backend.

Set these environment variables only when needed:

| Variable | Default | Purpose |
|---|---:|---|
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | unset | Export traces using OTLP/HTTP, e.g. `http://127.0.0.1:4318/v1/traces` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | Standard OTLP endpoint fallback |
| `OTEL_SERVICE_NAME` | `mcp-inspector` | Service name recognized by the OpenTelemetry SDK |
| `MCP_INSPECTOR_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |
| `MCP_INSPECTOR_MAX_FRAME_BYTES` | `16777216` | Maximum inspected JSON-RPC frame / SSE event in bytes |
| `MCP_INSPECTOR_RPC_TIMEOUT_MS` | `120000` | Pending request timeout, from 1 second to 1 hour |
| `MCP_INSPECTOR_MAX_PENDING_REQUESTS` | `10000` | Maximum pending RPC correlations per transport store |
| `MCP_INSPECTOR_SESSION_IDLE_MS` | `1800000` | Legacy HTTP session idle TTL, 1 minute to 24 hours |
| `MCP_INSPECTOR_PROXY_BEARER_TOKEN` | unset | Required for non-loopback proxy binds; use a high-entropy secret of at least 32 characters. This client credential is not forwarded upstream. |
| `MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN` | unset | Optional bearer token for the configured HTTP upstream |
| `MCP_INSPECTOR_UPSTREAM_TIMEOUT_MS` | `120000` | Upstream inactivity timeout, from 1 second to 1 hour |
| `MCP_INSPECTOR_ALLOWED_ORIGINS` | unset | Exact comma-separated canonical Origin allowlist; required for non-loopback binding and browser preflight |

The HTTP proxy binds to loopback by default. A non-loopback bind requires `--allow-remote`, a high-entropy `MCP_INSPECTOR_PROXY_BEARER_TOKEN` (minimum 32 characters), and an exact non-empty `MCP_INSPECTOR_ALLOWED_ORIGINS` allowlist. Requests must send `Authorization: Bearer <token>`; unauthenticated requests receive 401, and the proxy credential is removed before forwarding to the upstream. Configure upstream credentials separately with `MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN` or `MCP_INSPECTOR_UPSTREAM_HEADERS`. The shared token is not per-user authorization, and the proxy still does not provide TLS or rate limiting, so place a TLS-terminating, rate-limiting gateway in front before internet exposure. The proxy also validates Host authority syntax on every bind and enforces Origin validation in line with MCP Streamable HTTP security requirements.

Logs are structured JSON on stderr. Request arguments, prompts, and tool results are not logged or attached to spans. String JSON-RPC IDs are hashed before being used in metadata. Tool names, schema names, endpoint paths, server identity, error details, and exported traces can still be sensitive operational metadata; protect logs and collector access accordingly.

## Validation, CI, and performance

```bash
npm run check
npm test
npm run bench
npm run bench:e2e
npm audit --audit-level=high
```

- `npm run check` parses every project JavaScript file and validates JSON manifests.
- `npm test` runs unit tests, HTTP and stdio proxy integration tests, workflow-reference security tests, and—when dependencies are installed—official MCP SDK legacy/modern interoperability plus schema fuzzing tests.
- `npm run bench` measures JSON-RPC side-channel framing throughput. It is a microbenchmark, not an end-to-end latency claim.
- `npm run bench:e2e` compares serial MCP SDK round-trip latency direct to a fixture server and through the proxy, reporting p50/p95/p99 and median overhead. Use production-like hardware, fixtures, transports, collector settings, and load before setting acceptance thresholds.

GitHub Actions runs the checks, SDK-backed tests, dependency audit, and CycloneDX SBOM generation. Successful CI must be observed in the actual repository; a workflow file alone is not evidence that CI passed.

## Windows dependency repair helper

If you extracted an earlier bundle with the incompatible API pin, double-click `FIX_OTEL_DEPENDENCY.bat`. It repairs only that dependency entry and runs a normal `npm install`; it never disables peer-dependency checks. Then run `RUN_LOCAL_CHECKS.bat`.

## Windows publishing helper

`PUSH_TO_GITHUB.bat` checks Node, Git, and GitHub CLI; installs dependencies and generates the lockfile; runs checks/tests/audit and both benchmarks; generates an SBOM; then creates `mcp-inspector` in the authenticated GitHub account if it does not exist and pushes `main`. It asks whether the repository should be public or private when creating it. Inspect the generated SBOM and npm audit report before making the repository public.

The script cannot override organization policies, billing restrictions, branch protection, or missing permissions. Review the remote carefully if a repository with this name already exists.

## Design boundaries and roadmap

MCP Inspector is a protocol-aware observer and test harness, not a replacement MCP router, authentication gateway, policy engine, or guarantee that tools are safe. It does not infer model reasoning from provider internals; it correlates protocol events with explicit external trace metadata when supplied. JSON-RPC byte forwarding is preserved, but observation still consumes CPU and memory; “zero-copy” applies to the forwarding path rather than the parser's side-channel memory.

Before a stable 1.0 release, the project should add multi-version real-server test coverage, fuzz the proxy itself, test disconnect and cancellation behavior under load, validate HTTP Origin/Host policy for each deployment topology, establish stable latency/throughput budgets across CI hardware, publish signed release artifacts, and receive an independent security review.

## License

MIT. See [LICENSE](./LICENSE).
