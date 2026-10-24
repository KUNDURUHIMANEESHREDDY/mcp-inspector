import test from 'node:test';
import assert from 'node:assert/strict';
let generateSchemaCases;
let Ajv2020;
try {
  ({ generateSchemaCases } = await import('../src/fuzz/schema-cases.js'));
  ({ default: Ajv2020 } = await import('ajv/dist/2020.js'));
} catch (error) {
  // Allow a local, dependency-free run; CI must fail on missing or broken imports.
  if (process.env.CI === 'true' || error?.code !== 'ERR_MODULE_NOT_FOUND') throw error;
}

test('schema case generator returns schema-valid boundary candidates', { skip: !generateSchemaCases || !Ajv2020 }, () => {
  const schema = {
    type: 'object',
    required: ['path', 'mode'],
    additionalProperties: false,
    properties: {
      path: { type: 'string', minLength: 1, maxLength: 18 },
      mode: { type: 'string', enum: ['read', 'write'] },
      page: { type: 'integer', minimum: 1, maximum: 20 },
    },
  };
  const result = generateSchemaCases(schema, { maxCases: 20 });
  const ajv = new Ajv2020({ strict: false });
  const validate = ajv.compile(schema);
  assert.ok(result.cases.length > 0);
  assert.ok(result.cases.length <= 20);
  for (const candidate of result.cases) assert.equal(validate(candidate.arguments), true, candidate.label);
});

test('schema case generator reports unsupported schemas rather than crashing', { skip: !generateSchemaCases }, () => {
  const result = generateSchemaCases({ $ref: '#/missing' });
  assert.equal(Array.isArray(result.warnings), true);
});


test('schema case generator rejects unsafe budgets and oversized schemas', { skip: !generateSchemaCases }, () => {
  assert.throws(() => generateSchemaCases({ type: 'object' }, { maxCases: 0 }), /maxCases must be an integer/);
  assert.throws(() => generateSchemaCases({ type: 'object' }, { maxCases: 501 }), /maxCases must be an integer/);
  const result = generateSchemaCases({ type: 'string', description: 'x'.repeat(1_048_600) });
  assert.deepEqual(result.cases, []);
  assert.ok(result.warnings.includes('schema_too_large'));
});

test('schema candidate generation treats __proto__ as data, not a prototype mutation', { skip: !generateSchemaCases }, () => {
  const schema = JSON.parse('{"type":"object","required":["__proto__"],"properties":{"__proto__":{"type":"string","enum":["payload"]}}}');
  const result = generateSchemaCases(schema, { maxCases: 10 });
  const candidate = result.cases.find((item) => Object.hasOwn(item.arguments, '__proto__'));
  assert.ok(candidate, 'candidate should preserve an explicitly advertised __proto__ property');
  assert.equal(Object.getPrototypeOf(candidate.arguments), null);
  assert.equal(candidate.arguments.__proto__, 'payload');
  assert.equal({}.polluted, undefined);
});
