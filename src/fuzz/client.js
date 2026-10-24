import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { performance } from 'node:perf_hooks';
import { basename } from 'node:path';
import { generateSchemaCases } from './schema-cases.js';
import { createContract, contractHash, writeContract } from '../contracts/contract.js';
import { resolveWorkflowReferences } from '../workflows/references.js';
import { validateWorkflowInput } from '../workflows/validate.js';

function clientOptions(protocol) {
  if (protocol === 'auto') return { versionNegotiation: { mode: 'auto' } };
  if (protocol === 'modern') return { versionNegotiation: { mode: { pin: '2026-07-28' } } };
  return {};
}

export async function connectToServer(command, args, protocol = 'legacy') {
  if (!command) throw new Error('A server command is required after `--`');
  if (!['legacy', 'auto', 'modern'].includes(protocol)) throw new Error(`Unknown protocol mode: ${protocol}`);
  const client = new Client({ name: 'mcp-inspector', version: '0.1.0' }, clientOptions(protocol));
  const transport = new StdioClientTransport({ command, args });
  try {
    await client.connect(transport);
    return { client, transport };
  } catch (error) {
    try { await client.close(); } catch { /* Preserve the connection error. */ }
    throw error;
  }
}

export async function snapshotServer({ command, args, protocol = 'legacy', output }) {
  const { client } = await connectToServer(command, args, protocol);
  try {
    const { tools } = await client.listTools();
    // Do not persist raw argv or full executable paths: they can reveal credentials or private paths.
    const contract = createContract(tools, basename(command) || 'stdio-server');
    contract.protocolEra = client.getProtocolEra?.() ?? 'legacy-or-unknown';
    contract.serverInfo = client.getServerVersion?.() ?? null;
    contract.hash = contractHash(contract);
    if (output) await writeContract(output, contract);
    return contract;
  } finally {
    await client.close();
  }
}

export async function fuzzServer({ command, args, protocol = 'legacy', maxCases = 30, caseMode = 'valid', execute = false }) {
  if (!['valid', 'invalid', 'mixed'].includes(caseMode)) throw new Error('caseMode must be valid, invalid, or mixed');
  if (!Number.isInteger(maxCases) || maxCases < 1 || maxCases > 500) throw new RangeError('maxCases must be an integer from 1 to 500');
  if (caseMode === 'mixed' && maxCases < 2) throw new RangeError('mixed case mode requires maxCases >= 2');
  const { client } = await connectToServer(command, args, protocol);
  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    protocolEra: client.getProtocolEra?.() ?? 'legacy-or-unknown',
    server: client.getServerVersion?.() ?? null,
    dryRun: !execute,
    caseMode,
    totalCandidates: 0,
    executed: 0,
    tools: [],
  };
  try {
    const { tools } = await client.listTools();
    const remaining = maxCases;
    for (const tool of tools) {
      if (report.totalCandidates >= remaining) break;
      const generated = generateSchemaCases(tool.inputSchema ?? { type: 'object' }, {
        maxCases: Math.min(remaining - report.totalCandidates, 30),
        mode: caseMode,
      });
      const item = {
        tool: tool.name,
        candidate_count: generated.cases.length,
        warnings: generated.warnings,
        cases: generated.cases.map((testCase) => ({ label: testCase.label, valid_by_schema: testCase.validBySchema === true })),
      };
      report.totalCandidates += generated.cases.length;
      if (execute) {
        item.results = [];
        for (const testCase of generated.cases) {
          const started = performance.now();
          try {
            const result = await client.callTool({ name: tool.name, arguments: testCase.arguments }, { timeout: 15_000 });
            item.results.push({
              label: testCase.label,
              duration_ms: Number((performance.now() - started).toFixed(3)),
              tool_reported_error: result?.isError === true,
              outcome: result?.isError === true ? 'tool_error' : 'completed',
            });
          } catch (error) {
            item.results.push({
              label: testCase.label,
              duration_ms: Number((performance.now() - started).toFixed(3)),
              outcome: 'protocol_error',
              error_type: error?.name ?? 'Error',
            });
          }
          report.executed += 1;
        }
      }
      report.tools.push(item);
    }
  } finally {
    await client.close();
  }
  return report;
}

export async function runWorkflow({ command, args, protocol = 'legacy', workflow, execute = false }) {
  validateWorkflowInput(workflow);
  const { client } = await connectToServer(command, args, protocol);
  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    workflow: workflow.name || 'unnamed-workflow',
    protocolEra: client.getProtocolEra?.() ?? 'legacy-or-unknown',
    dryRun: !execute,
    steps: [],
  };
  try {
    const { tools } = await client.listTools();
    const available = new Map(tools.map((tool) => [tool.name, tool]));
    const completedResults = new Map();
    const steps = workflow.steps ?? [];
    const stepIndices = new Map();
    steps.forEach((step, index) => {
      const id = typeof step?.id === 'string' && step.id ? step.id : `step-${index + 1}`;
      if (stepIndices.has(id)) throw new Error(`Duplicate workflow step id: ${id}`);
      stepIndices.set(id, index);
    });

    for (const [index, step] of steps.entries()) {
      const id = typeof step?.id === 'string' && step.id ? step.id : `step-${index + 1}`;
      if (!step || typeof step.tool !== 'string' || typeof step.arguments !== 'object' || step.arguments === null || Array.isArray(step.arguments)) {
        throw new Error(`Invalid workflow step at index ${index}`);
      }
      const tool = available.get(step.tool);
      if (!tool) {
        report.steps.push({ id, tool: step.tool, outcome: 'unknown_tool' });
        continue;
      }

      const referenceResult = resolveWorkflowReferences(step.arguments, completedResults, stepIndices, index);
      const row = {
        id,
        tool: step.tool,
        reference_count: referenceResult.referenceCount,
      };
      if (referenceResult.unresolved.length > 0) {
        row.unresolved_references = referenceResult.unresolved.slice(0, 50);
        row.outcome = execute ? 'skipped_unresolved_reference' : 'dry_run_unresolved_dependency';
        report.steps.push(row);
        continue;
      }

      const ajvMatch = await validateArguments(tool.inputSchema ?? { type: 'object' }, referenceResult.value);
      row.schema_valid = ajvMatch.valid;
      if (!ajvMatch.valid) row.validation_errors = ajvMatch.errors;
      if (execute && ajvMatch.valid) {
        const started = performance.now();
        try {
          const result = await client.callTool({ name: step.tool, arguments: referenceResult.value }, { timeout: 30_000 });
          row.duration_ms = Number((performance.now() - started).toFixed(3));
          row.outcome = result?.isError === true ? 'tool_error' : 'completed';
          // Only successful responses may be used as downstream workflow inputs.
          if (result?.isError !== true) completedResults.set(id, result);
        } catch (error) {
          row.duration_ms = Number((performance.now() - started).toFixed(3));
          row.outcome = 'protocol_error';
          row.error_type = error?.name ?? 'Error';
        }
      } else {
        row.outcome = execute ? 'skipped_invalid_arguments' : 'dry_run';
      }
      report.steps.push(row);
    }
  } finally {
    await client.close();
  }
  return report;
}


function validateArguments(schema, argumentsValue) {
  // The dedicated generator compiles schemas with all supported JSON Schema formats.
  // This single-input validator intentionally returns messages only, never argument values.
  return validateJsonSchema(schema, argumentsValue);
}

function validateJsonSchema(schema, value) {
  // Local dynamic import keeps the CLI's proxy-only startup lean.
  return import('ajv/dist/2020.js').then(async ({ default: Ajv2020 }) => {
    const { default: addFormats } = await import('ajv-formats');
    const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: true, allowUnionTypes: true });
    addFormats(ajv);
    let validator;
    try {
      validator = ajv.compile(schema ?? { type: 'object' });
    } catch (error) {
      return { valid: false, errors: [`unsupported_schema:${error?.name ?? 'compile_error'}`] };
    }
    const valid = validator(value);
    return { valid, errors: (validator.errors ?? []).slice(0, 20).map((error) => `${error.instancePath || '/'} ${error.keyword}`) };
  });
}

