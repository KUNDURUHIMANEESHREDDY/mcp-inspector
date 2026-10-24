import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

function addCandidate(candidates, label, value) {
  candidates.push({ label, arguments: value });
}

function repeated(character, count) {
  return character.repeat(Math.max(0, Math.min(256, count)));
}

function seedValues(schema, depth = 0) {
  if (!schema || typeof schema !== 'object' || depth > 8) return [null];
  if (Object.hasOwn(schema, 'const')) return [schema.const];
  if (Array.isArray(schema.enum) && schema.enum.length) return schema.enum.slice(0, 24);
  for (const key of ['oneOf', 'anyOf']) {
    if (Array.isArray(schema[key])) return schema[key].slice(0, 8).flatMap((child) => seedValues(child, depth + 1));
  }
  if (Array.isArray(schema.allOf)) {
    const merged = Object.assign(Object.create(null), ...schema.allOf.filter((part) => part && typeof part === 'object'));
    return seedValues({ ...merged, ...schema, allOf: undefined }, depth + 1);
  }

  const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;
  if (type === 'object' || schema.properties) {
    const properties = schema.properties ?? {};
    const required = new Set(schema.required ?? []);
    const minimal = Object.create(null);
    const complete = Object.create(null);
    for (const [name, propertySchema] of Object.entries(properties)) {
      const values = seedValues(propertySchema, depth + 1);
      if (required.has(name)) minimal[name] = values[0];
      if (values.length) complete[name] = values[0];
    }
    if (Object.keys(minimal).length < (schema.minProperties ?? 0)) {
      for (const [name, value] of Object.entries(complete)) {
        if (!Object.hasOwn(minimal, name)) minimal[name] = value;
        if (Object.keys(minimal).length >= Math.min(schema.minProperties, 256)) break;
      }
    }
    return Object.keys(minimal).length === Object.keys(complete).length ? [complete] : [minimal, complete];
  }
  if (type === 'array') {
    const minItems = Math.min(Math.max(0, schema.minItems ?? 0), 4);
    const itemSchema = schema.items ?? {};
    const base = seedValues(itemSchema, depth + 1)[0];
    return [Array.from({ length: minItems }, () => base), Array.from({ length: Math.max(minItems, 1) }, () => base)];
  }
  if (type === 'string') {
    const min = Math.min(Math.max(0, schema.minLength ?? 0), 256);
    const candidates = [repeated('a', min), 'x', 'test', 'user@example.test', '2026-01-01T00:00:00Z', '0'];
    if (Number.isInteger(schema.maxLength) && schema.maxLength <= 256) candidates.push(repeated('x', schema.maxLength));
    return candidates;
  }
  if (type === 'integer' || type === 'number') {
    const candidates = [0, 1, -1];
    if (Number.isFinite(schema.minimum)) candidates.push(schema.minimum);
    if (Number.isFinite(schema.maximum)) candidates.push(schema.maximum);
    if (Number.isFinite(schema.exclusiveMinimum)) candidates.push(schema.exclusiveMinimum + (type === 'integer' ? 1 : Math.max(Number.EPSILON, Math.abs(schema.exclusiveMinimum) * Number.EPSILON)));
    if (Number.isFinite(schema.exclusiveMaximum)) candidates.push(schema.exclusiveMaximum - (type === 'integer' ? 1 : Math.max(Number.EPSILON, Math.abs(schema.exclusiveMaximum) * Number.EPSILON)));
    if (type === 'integer') return candidates.filter(Number.isFinite).map(Math.ceil);
    return candidates.filter(Number.isFinite);
  }
  if (type === 'boolean') return [false, true];
  if (type === 'null') return [null];
  if (Array.isArray(schema.type)) return schema.type.slice(0, 4).flatMap((entry) => seedValues({ ...schema, type: entry }, depth + 1));
  return [{}];
}

function mutateObjectCandidates(schema, base, candidates, maxCandidates) {
  if (!schema?.properties || !base || typeof base !== 'object' || Array.isArray(base)) return;
  for (const [name, propertySchema] of Object.entries(schema.properties)) {
    const values = seedValues(propertySchema);
    for (let index = 1; index < values.length && candidates.length < maxCandidates; index += 1) {
      if (Object.hasOwn(base, name) || (schema.required ?? []).includes(name)) {
        addCandidate(candidates, `boundary:${name}:${index}`, { ...base, [name]: values[index] });
      } else {
        addCandidate(candidates, `optional:${name}:${index}`, { ...base, [name]: values[index] });
      }
    }
  }
}

function invalidSeeds(schema) {
  const cases = [];
  const add = (label, value) => cases.push({ label, arguments: value });
  const type = Array.isArray(schema?.type) ? schema.type[0] : schema?.type;

  if (type === 'object' || schema?.properties) {
    const properties = schema.properties ?? {};
    const required = new Set(schema.required ?? []);
    const base = Object.create(null);
    for (const name of required) {
      const property = properties[name] ?? {};
      base[name] = seedValues(property)[0];
    }
    add('invalid:missing-required-properties', {});
    for (const name of required) {
      const candidate = { ...base };
      delete candidate[name];
      add(`invalid:missing-required:${name}`, candidate);
    }
    for (const [name, property] of Object.entries(properties)) {
      const propertyType = Array.isArray(property?.type) ? property.type[0] : property?.type;
      let wrongValue;
      if (Array.isArray(property?.enum) || Object.hasOwn(property ?? {}, 'const')) {
        const disallowed = ['__mcp_inspector_invalid_enum__', null, 987654321, { unexpected: true }];
        wrongValue = disallowed.find((value) => !((property.enum ?? []).some((entry) => JSON.stringify(entry) === JSON.stringify(value)) || (Object.hasOwn(property ?? {}, 'const') && JSON.stringify(property.const) === JSON.stringify(value))));
      } else if (propertyType === 'string') wrongValue = 42;
      else if (propertyType === 'integer' || propertyType === 'number') wrongValue = 'not-a-number';
      else if (propertyType === 'boolean') wrongValue = 'not-a-boolean';
      else if (propertyType === 'array') wrongValue = { not: 'an-array' };
      else if (propertyType === 'object' || property.properties) wrongValue = null;
      else if (propertyType === 'null') wrongValue = false;
      else wrongValue = '__mcp_inspector_invalid_type__';
      add(`invalid:type-or-enum:${name}`, { ...base, [name]: wrongValue });

      if (propertyType === 'string' && Number.isInteger(property.minLength) && property.minLength > 0) {
        add(`invalid:minLength:${name}`, { ...base, [name]: repeated('x', property.minLength - 1) });
      }
      if (propertyType === 'string' && Number.isInteger(property.maxLength) && property.maxLength < 16_384) {
        add(`invalid:maxLength:${name}`, { ...base, [name]: repeated('x', property.maxLength + 1) });
      }
      if ((propertyType === 'integer' || propertyType === 'number') && Number.isFinite(property.minimum)) {
        add(`invalid:minimum:${name}`, { ...base, [name]: property.minimum - (propertyType === 'integer' ? 1 : Math.max(Number.EPSILON, Math.abs(property.minimum) * Number.EPSILON)) });
      }
      if ((propertyType === 'integer' || propertyType === 'number') && Number.isFinite(property.maximum)) {
        add(`invalid:maximum:${name}`, { ...base, [name]: property.maximum + (propertyType === 'integer' ? 1 : Math.max(Number.EPSILON, Math.abs(property.maximum) * Number.EPSILON)) });
      }
    }
    if (schema.additionalProperties === false) add('invalid:unexpected-property', { ...base, __mcp_inspector_unexpected__: true });
  } else {
    const wrongTopLevel = [null, {}, [], true, 'invalid-type', 1];
    wrongTopLevel.forEach((value, index) => add(`invalid:top-level-type:${index}`, value));
    if (type === 'string' && Number.isInteger(schema.minLength) && schema.minLength > 0) add('invalid:top-level-minLength', repeated('x', schema.minLength - 1));
    if (type === 'string' && Number.isInteger(schema.maxLength) && schema.maxLength < 16_384) add('invalid:top-level-maxLength', repeated('x', schema.maxLength + 1));
  }
  return cases;
}

export function generateSchemaCases(schema, { maxCases = 30, mode = 'valid' } = {}) {
  if (!Number.isInteger(maxCases) || maxCases < 1 || maxCases > 500) {
    throw new RangeError('maxCases must be an integer from 1 to 500');
  }
  const limit = maxCases;
  let serializedSchema;
  try { serializedSchema = JSON.stringify(schema ?? { type: 'object' }); }
  catch { return { cases: [], warnings: ['schema_not_serializable'] }; }
  if (Buffer.byteLength(serializedSchema, 'utf8') > 1_048_576) {
    return { cases: [], warnings: ['schema_too_large'] };
  }
  if (!['valid', 'invalid', 'mixed'].includes(mode)) {
    return { cases: [], warnings: ['unsupported_case_mode'] };
  }
  const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: true, allowUnionTypes: true });
  addFormats(ajv);
  const inputSchema = schema && typeof schema === 'object' ? schema : { type: 'object' };
  let validate;
  const warnings = [];
  try {
    validate = ajv.compile(inputSchema);
  } catch (error) {
    return { cases: [], warnings: [`unsupported_schema:${error?.name ?? 'compile_error'}`] };
  }

  const candidates = [];
  const seeds = seedValues(inputSchema);
  seeds.forEach((value, index) => addCandidate(candidates, index === 0 ? 'schema-seed' : `schema-alternative:${index}`, value));
  if (seeds[0] && typeof seeds[0] === 'object' && !Array.isArray(seeds[0])) {
    mutateObjectCandidates(inputSchema, seeds[0], candidates, limit * 5);
  }
  if (inputSchema.type === 'object' || inputSchema.properties) {
    const minimal = Object.create(null);
    for (const name of inputSchema.required ?? []) {
      minimal[name] = seedValues(inputSchema.properties?.[name])[0];
    }
    addCandidate(candidates, 'required-fields', minimal);
  }

  const validateCandidates = (entries, shouldBeValid, budget) => {
    const accepted = [];
    const seen = new Set();
    for (const candidate of entries) {
      let key;
      try { key = JSON.stringify(candidate.arguments); } catch { continue; }
      if (seen.has(key)) continue;
      seen.add(key);
      let valid = false;
      try { valid = Boolean(validate(candidate.arguments)); } catch (error) {
        warnings.push(`validation_error:${error?.name ?? 'unknown'}`);
      }
      if (valid === shouldBeValid) accepted.push({ ...candidate, validBySchema: valid });
      if (accepted.length >= budget) break;
    }
    return accepted;
  };

  const validCandidates = mode === 'invalid' ? [] : validateCandidates(candidates, true, mode === 'mixed' ? Math.ceil(limit / 2) : limit);
  const invalidCandidates = mode === 'valid' ? [] : validateCandidates(invalidSeeds(inputSchema), false, mode === 'mixed' ? Math.floor(limit / 2) : limit);
  const accepted = mode === 'mixed' ? [...validCandidates, ...invalidCandidates].slice(0, limit) : (mode === 'valid' ? validCandidates : invalidCandidates);
  if (mode !== 'invalid' && validCandidates.length === 0) warnings.push('no_schema-valid_candidates_generated');
  if (mode !== 'valid' && invalidCandidates.length === 0) warnings.push('no_schema-invalid_candidates_generated');
  return { cases: accepted, warnings: [...new Set(warnings)] };
}
