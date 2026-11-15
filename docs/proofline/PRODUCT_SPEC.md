# Proofline — Product and Architecture Spec

**Status:** Initial implementation plan  
**Target:** Atlassian Codegeist 2026 — Apps for Software Teams  
**Working repository:** `mcp-inspector` (evidence adapter); Forge app will be a separate deployable app/package once its repository boundary is established.

## Product statement

Proofline gives each Jira issue an evidence-backed completion status. It does not accept an agent's statement that work is done as proof. It derives a verdict from attributable, persisted evidence tied to explicit acceptance criteria.

**Core promise:** A Jira issue is not *verified complete* until every required criterion has passing evidence and no required criterion has failing evidence.

## User and problem

- **Primary user:** engineering lead, QA engineer, or developer responsible for accepting work.
- **Workflow:** a Jira issue moves through implementation and verification; CI and engineering tools produce evidence; Proofline aggregates that evidence and explains whether the issue is ready.
- **Pain:** Jira status and agent summaries can say "Done" while tests, security checks, or required validation are missing or failing.

## MVP experience

1. An engineer opens a Jira issue and sees a Proofline Evidence Passport.
2. The issue has an explicit, non-empty list of required criteria (initially configured in Proofline).
3. A trusted evidence source submits a result for one criterion.
4. Proofline validates the source, persists the evidence record, and derives the verdict.
5. The issue panel shows PASS, FAIL, or INDETERMINATE, with evidence, timestamps, source identifiers, and missing/failed criteria.
6. A reviewer can inspect why the verdict was derived. No AI-generated statement can directly set a verdict.

### Initial evidence sources

- **CI evidence:** first-party GitHub Actions workflow or a small signed webhook adapter. This is the authoritative source for test/build/security outcomes.
- **MCP Inspector:** optional operational evidence (tool invocation metadata, protocol errors, latency, contract hash). MCP Inspector currently deliberately avoids recording tool arguments and results by default. Its successful tool invocation must never be interpreted as proof that a test or requirement passed.
- **Manual evidence:** excluded from automatic PASS in the first MVP; if later supported, it must be visibly labeled and governed by an explicit policy.

## Verdict contract

Use the existing No Presumed Pass semantics as the reference:

- **PASS:** every required criterion has explicit passing evidence and no required criterion has failing evidence.
- **FAIL:** at least one required criterion has explicit failing evidence.
- **INDETERMINATE:** required evidence is missing, the policy is empty, or evidence cannot establish a verdict.
- A failure wins over a pass for the same required criterion until a separately specified resolution policy exists.
- Evidence for an unconfigured criterion is visible as unmatched and cannot satisfy a required criterion.
- The verdict is computed by Proofline; callers cannot submit a verdict status.

## Evidence envelope (v1 proposal)

```json
{
  "schemaVersion": 1,
  "recordType": "verification",
  "evidenceId": "ci:run-842:unit-tests",
  "issueKey": "PAY-142",
  "criterionKey": "unit-tests",
  "outcome": "PASS",
  "source": "github-actions",
  "sourceRunId": "842",
  "observedAt": "2026-11-15T08:00:00Z",
  "artifact": {
    "uri": "https://example.invalid/artifacts/run-842",
    "sha256": "..."
  },
  "verifier": {
    "name": "proofline-github-actions-adapter",
    "version": "0.1.0"
  },
  "summary": "Unit test job completed successfully."
}
```

The example is illustrative; the actual schema must validate identifiers, timestamps, enum values, URL policy, digest format, payload size, and duplicate IDs. Evidence must include a source run/receipt identifier. Do not accept arbitrary caller-supplied `outcome` values without validating the authenticated source's signed payload or adapter-specific provenance.

## Architecture

- **Forge app (new deployable app):** Jira issue panel, issue/criterion configuration, evidence ingestion handler, evidence query, verdict derivation, optional Rovo reviewer.
- **Forge storage:** per-installation evidence records and policy. Use unique evidence IDs and fail-if-exists writes for append behavior. This is application-level append-only behavior, not cryptographic immutability against administrators or platform operators.
- **Ingress:** Forge web trigger for external evidence. Web trigger URLs are not authenticated by Forge by default; implement and test request authentication in the handler. Prefer HMAC over raw request bytes, timestamp freshness, replay protection, and per-installation secret rotation. Never put secrets in URLs or client-side assets.
- **MCP Inspector (this repository):** retain its local-first proxy and protocol telemetry. Add an opt-in, redacted evidence export only after the envelope and trust model are stable. Never export prompts, tool arguments, or results by default.
- **No Presumed Pass:** port the small deterministic verdict contract to the Forge runtime with parity tests against the Python implementation. Do not attempt to run its loopback-only Python HTTP API inside Forge.
- **Later, not MVP:** Watch-dogs (Windows-only terminal evidence), DataOS relationship graph, MLAC signed worker attestations, workflow transition blocking, Bitbucket/Confluence connectors, and broad multi-source support.

## Atlassian implementation

Required Forge foundation:
- `jira:issuePanel` — display the Evidence Passport on a Jira issue.
- Forge resolver/function — read the current issue context, policy, evidence, and derived verdict.
- Forge hosted storage — persist policy and evidence scoped to the installation.

Follow-on:
- `rovo:agent` — Evidence Reviewer that explains missing or conflicting evidence using the derived report.
- `rovo:mcp` — expose read-only verification tools after the core app works. Current Rovo MCP is Preview; treat it as a bonus integration, not a critical path.
- Do not depend on the Preview Jira workflow validator for the MVP. First demonstrate reliable verdicts and a clear issue panel.

## Security and correctness requirements

- Never trust a model-generated verdict or a client-provided status.
- Authenticate every external evidence submission; reject missing/invalid signatures.
- Enforce timestamp freshness and idempotency/replay protection.
- Scope all records and policies to the Forge installation and Jira issue.
- Validate payloads strictly; reject duplicate JSON keys, unknown outcomes, malformed timestamps, oversized payloads, and invalid digests.
- Keep secrets server-side and support rotation.
- Do not store prompts, tool arguments, or raw tool results by default.
- Preserve contradictory evidence; do not silently overwrite or delete a failure.
- Expose evidence provenance and explain every verdict.
- Treat links and artifact references as untrusted; do not fetch arbitrary URLs from evidence records.

## Delivery plan and dependency graph

1. **Contract and threat model** — finalize evidence JSON schema, source trust levels, replay protection, and verdict parity tests. Blocks all ingestion work.
2. **Forge app skeleton** — manifest, Jira issue panel, resolver, local Forge test/deploy instructions. Can proceed alongside contract work.
3. **Policy and verdict core** — required criteria CRUD, deterministic three-valued verdict engine, unit tests.
4. **Evidence persistence and ingress** — per-installation storage, authenticated web trigger, duplicate rejection, audit view.
5. **MCP Inspector adapter** — opt-in export of protocol metadata only; integration tests against a fixture MCP server.
6. **Jira end-to-end demo** — seed a sample issue, submit pass/fail/missing evidence, render verdict and provenance.
7. **Rovo integration** — read-only Evidence Reviewer and optional Rovo MCP tools after the deterministic flow is stable.
8. **Submission hardening** — install link, judge setup guide, security review, demo video under five minutes, reproducible test evidence.

### First vertical slice

One sample Jira issue with three required criteria: `build`, `unit-tests`, and `security-scan`. Submit PASS for build and unit tests, FAIL for security scan, and show an overall FAIL with the exact evidence. Then remove the failure only through a new, attributable passing run plus an explicit resolution policy; never mutate the original record. A second scenario with no security evidence must show INDETERMINATE, not PASS.

## Acceptance criteria for MVP

- [ ] Forge app installs in a test Jira site and renders an issue panel.
- [ ] A non-empty required-criteria policy can be stored per issue.
- [ ] Evidence ingestion rejects unauthenticated, malformed, oversized, stale, and duplicate records.
- [ ] Evidence records cannot be overwritten through normal app operations.
- [ ] PASS / FAIL / INDETERMINATE matches the No Presumed Pass reference semantics.
- [ ] Missing evidence never produces PASS; an empty policy is INDETERMINATE.
- [ ] Contradictory evidence is preserved and a failure takes precedence.
- [ ] Issue panel explains the verdict and links every displayed result to its evidence source.
- [ ] MCP Inspector telemetry is never misrepresented as proof of test success.
- [ ] Automated tests cover the contract, authentication, replay, tenancy boundaries, and end-to-end verdict flow.

## Open decisions

- Final product name and app repository boundary.
- Which source provides the first production-grade CI attestation (GitHub Actions first is proposed).
- Whether Forge SQL or Custom Entity Store is the best fit after validating quotas and query patterns.
- Exact webhook authentication scheme and key-rotation procedure.
- Whether Rovo MCP Preview is stable enough for the submission bonus path.
