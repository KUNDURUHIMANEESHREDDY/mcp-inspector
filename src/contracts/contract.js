import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { log } from '../observability/logger.js';

const MAX_CONTRACT_BYTES = 8 * 1024 * 1024;

export function stableJson(value) {
  if (value === undefined) return '"[undefined]"';
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function contractHash(contract) {
  const copy = { ...contract };
  delete copy.capturedAt;
  delete copy.hash;
  return createHash('sha256').update(stableJson(copy)).digest('hex');
}

export function createContract(tools, source = 'unknown') {
  const sorted = [...tools]
    .filter((tool) => tool && typeof tool.name === 'string')
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((tool) => ({
      name: tool.name,
      ...(tool.description ? { description: tool.description } : {}),
      ...(tool.inputSchema ? { inputSchema: tool.inputSchema } : {}),
      ...(tool.outputSchema ? { outputSchema: tool.outputSchema } : {}),
      ...(tool.annotations ? { annotations: tool.annotations } : {}),
    }));
  const contract = {
    schemaVersion: 1,
    source: String(source ?? 'unknown').slice(0, 256),
    capturedAt: new Date().toISOString(),
    tools: sorted,
  };
  contract.hash = contractHash(contract);
  return contract;
}

function asSet(value) {
  return new Set(Array.isArray(value) ? value.map(stableJson) : []);
}

function compareSchema(previous, current, path, changes) {
  if (stableJson(previous) === stableJson(current)) return;
  if (!previous || !current || typeof previous !== 'object' || typeof current !== 'object') {
    changes.push({ breaking: true, path, reason: 'schema changed to a different primitive or shape' });
    return;
  }

  if (current.type && (!previous.type || stableJson(previous.type) !== stableJson(current.type))) {
    changes.push({ breaking: true, path: `${path}.type`, reason: previous.type ? 'schema type changed' : 'a type restriction was introduced' });
  }
  if (previous.format !== current.format && current.format) {
    changes.push({ breaking: true, path: `${path}.format`, reason: 'a format constraint was introduced or changed' });
  }
  if (current.uniqueItems === true && previous.uniqueItems !== true) {
    changes.push({ breaking: true, path: `${path}.uniqueItems`, reason: 'arrays are now required to contain unique items' });
  }
  if (previous.pattern !== current.pattern && current.pattern) {
    changes.push({ breaking: true, path: `${path}.pattern`, reason: 'a pattern constraint was introduced or changed' });
  }

  if (Array.isArray(previous.enum) && Array.isArray(current.enum)) {
    const before = asSet(previous.enum);
    const after = asSet(current.enum);
    if ([...before].some((entry) => !after.has(entry))) {
      changes.push({ breaking: true, path: `${path}.enum`, reason: 'one or more previously allowed enum values were removed' });
    }
  } else if (Array.isArray(previous.enum) && !Array.isArray(current.enum)) {
    // Removing an enum widens what can be expressed, so this is not breaking.
  } else if (!Array.isArray(previous.enum) && Array.isArray(current.enum)) {
    changes.push({ breaking: true, path: `${path}.enum`, reason: 'an enum restriction was introduced' });
  }

  for (const key of ['minimum', 'exclusiveMinimum', 'minLength', 'minItems', 'minProperties']) {
    if (typeof current[key] === 'number' && (typeof previous[key] !== 'number' || current[key] > previous[key])) {
      changes.push({ breaking: true, path: `${path}.${key}`, reason: 'lower bound became stricter' });
    }
  }
  for (const key of ['maximum', 'exclusiveMaximum', 'maxLength', 'maxItems', 'maxProperties']) {
    if (typeof current[key] === 'number' && (typeof previous[key] !== 'number' || current[key] < previous[key])) {
      changes.push({ breaking: true, path: `${path}.${key}`, reason: 'upper bound became stricter' });
    }
  }
  if (current.additionalProperties === false && previous.additionalProperties !== false) {
    changes.push({ breaking: true, path: `${path}.additionalProperties`, reason: 'additional properties are now rejected' });
  }

  const beforeRequired = new Set(previous.required ?? []);
  const afterRequired = new Set(current.required ?? []);
  for (const name of afterRequired) {
    if (!beforeRequired.has(name)) {
      changes.push({ breaking: true, path: `${path}.required`, reason: `property '${name}' became required` });
    }
  }

  const beforeProperties = previous.properties ?? {};
  const afterProperties = current.properties ?? {};
  for (const name of Object.keys(beforeProperties)) {
    if (!(name in afterProperties)) {
      changes.push({ breaking: true, path: `${path}.properties.${name}`, reason: 'input property was removed' });
    } else {
      compareSchema(beforeProperties[name], afterProperties[name], `${path}.properties.${name}`, changes);
    }
  }
  for (const name of Object.keys(afterProperties)) {
    if (!(name in beforeProperties)) {
      changes.push({ breaking: false, path: `${path}.properties.${name}`, reason: afterRequired.has(name) ? 'new property is required' : 'optional property added' });
    }
  }

  if (previous.items && current.items) compareSchema(previous.items, current.items, `${path}.items`, changes);
  for (const key of ['oneOf', 'anyOf', 'allOf']) {
    if (stableJson(previous[key] ?? null) !== stableJson(current[key] ?? null)) {
      changes.push({ breaking: true, path: `${path}.${key}`, reason: 'schema alternatives changed; review compatibility manually' });
    }
  }
}

export function compareContracts(previous, current) {
  const changes = [];
  const before = new Map((previous.tools ?? []).map((tool) => [tool.name, tool]));
  const after = new Map((current.tools ?? []).map((tool) => [tool.name, tool]));

  for (const name of before.keys()) {
    if (!after.has(name)) changes.push({ breaking: true, path: `tools.${name}`, reason: 'tool was removed' });
  }
  for (const [name, tool] of after) {
    if (!before.has(name)) {
      changes.push({ breaking: false, path: `tools.${name}`, reason: 'tool was added' });
      continue;
    }
    const oldTool = before.get(name);
    if (stableJson(oldTool.inputSchema ?? {}) !== stableJson(tool.inputSchema ?? {})) {
      compareSchema(oldTool.inputSchema ?? {}, tool.inputSchema ?? {}, `tools.${name}.inputSchema`, changes);
    }
    if (stableJson(oldTool.outputSchema ?? null) !== stableJson(tool.outputSchema ?? null)) {
      if (oldTool.outputSchema && tool.outputSchema) {
        compareSchema(oldTool.outputSchema, tool.outputSchema, `tools.${name}.outputSchema`, changes);
      } else {
        changes.push({ breaking: true, path: `tools.${name}.outputSchema`, reason: 'output schema was added or removed' });
      }
    }
    if (oldTool.description !== tool.description) {
      changes.push({ breaking: false, path: `tools.${name}.description`, reason: 'tool description changed; review instruction compatibility' });
    }
    if (stableJson(oldTool.annotations ?? {}) !== stableJson(tool.annotations ?? {})) {
      const beforeHints = oldTool.annotations ?? {};
      const afterHints = tool.annotations ?? {};
      const riskIncreased = (beforeHints.readOnlyHint === true && afterHints.readOnlyHint !== true)
        || (beforeHints.destructiveHint === false && afterHints.destructiveHint === true)
        || (beforeHints.idempotentHint === true && afterHints.idempotentHint !== true)
        || (beforeHints.openWorldHint === false && afterHints.openWorldHint === true);
      changes.push({
        breaking: riskIncreased,
        securityReview: true,
        path: `tools.${name}.annotations`,
        reason: riskIncreased ? 'tool safety annotation became less restrictive; review before deployment' : 'tool annotations changed; review safety semantics',
      });
    }
  }
  return {
    breaking: changes.some((change) => change.breaking),
    changes,
    summary: {
      breaking: changes.filter((change) => change.breaking).length,
      compatible: changes.filter((change) => !change.breaking).length,
    },
  };
}

export async function readContract(path) {
  const metadata = await stat(path);
  if (metadata.size > MAX_CONTRACT_BYTES) throw new Error(`Contract file exceeds ${MAX_CONTRACT_BYTES} bytes: ${path}`);
  const raw = await readFile(path, 'utf8');
  const contract = JSON.parse(raw);
  if (!contract || contract.schemaVersion !== 1 || !Array.isArray(contract.tools)) {
    throw new Error(`Unsupported or invalid contract file: ${path}`);
  }
  if (typeof contract.hash !== 'string' || !/^[a-f0-9]{64}$/.test(contract.hash) || contract.hash !== contractHash(contract)) {
    throw new Error(`Contract integrity check failed or hash is missing: ${path}`);
  }
  return contract;
}

export async function writeContract(path, contract) {
  const serialized = `${JSON.stringify(contract, null, 2)}\n`;
  if (Buffer.byteLength(serialized, 'utf8') > MAX_CONTRACT_BYTES) {
    throw new Error(`Contract exceeds ${MAX_CONTRACT_BYTES} bytes and was not written`);
  }
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, serialized, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await rename(temporary, path);
  } catch (error) {
    try { await (await import('node:fs/promises')).unlink(temporary); } catch { /* Nothing to clean up. */ }
    throw error;
  }
}

export class ContractRecorder {
  constructor({ path, source = 'mcp-server', update = false } = {}) {
    this.path = path;
    this.source = source;
    this.update = update;
    this.pages = new Map();
  }

  async observeToolsList(requestParams, result, scope = 'default') {
    if (!Array.isArray(result?.tools)) return;
    const cursor = typeof requestParams?.cursor === 'string' ? requestParams.cursor : undefined;
    if (!this.pages.has(scope)) this.pages.set(scope, new Map());
    const pageSet = this.pages.get(scope);
    if (!cursor) pageSet.clear();
    pageSet.set(cursor ?? '__first__', result.tools);
    const allTools = [...pageSet.values()].flat();
    let serializedBytes;
    try { serializedBytes = Buffer.byteLength(JSON.stringify(allTools), 'utf8'); }
    catch { this.pages.delete(scope); log('warn', 'contract.capture_skipped', { source: this.source, reason: 'serialization_error' }); return; }
    if (allTools.length > 10_000 || serializedBytes > MAX_CONTRACT_BYTES) {
      this.pages.delete(scope);
      log('warn', 'contract.capture_skipped', { source: this.source, reason: 'contract_limit', tool_count: allTools.length, bytes: serializedBytes });
      return;
    }
    if (typeof result.nextCursor === 'string' && result.nextCursor.length > 0) return;

    this.pages.delete(scope);
    const current = createContract(allTools, this.source);
    if (!this.path) {
      log('info', 'contract.captured', { source: this.source, tool_count: current.tools.length, hash: current.hash });
      return;
    }
    try {
      const baseline = await readContract(this.path);
      const report = compareContracts(baseline, current);
      log(report.breaking ? 'warn' : 'info', 'contract.diff', {
        source: this.source,
        baseline_hash: baseline.hash,
        current_hash: current.hash,
        tool_count: current.tools.length,
        breaking: report.breaking,
        change_count: report.changes.length,
        changes: report.changes.slice(0, 100),
      });
      if (this.update) await writeContract(this.path, current);
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        log('warn', 'contract.baseline_unreadable', { source: this.source, error_type: error?.name ?? 'Error' });
        return;
      }
      await writeContract(this.path, current);
      log('info', 'contract.baseline_created', { source: this.source, path: this.path, tool_count: current.tools.length, hash: current.hash });
    }
  }
}
