# Changelog

All notable changes to MCP Inspector are documented here.

## Unreleased

- Add a read-only protocol compatibility suite across stdio and Streamable HTTP transports and legacy, automatic, and modern protocol negotiation.
- Validate JSON-RPC 2.0 envelopes and produce deterministic pass/fail compatibility reports.
- Extend dashboard summaries with p99 latency, recent request throughput, response error rate, timeout count, schema-drift count, and repeated-failure groups.
- Add explicit workbench execution limits, cancellation, and progress reporting to fuzz and workflow commands.
- Add a security model, secret-safe event regression tests, browser E2E coverage, and tagged release artifact automation.
