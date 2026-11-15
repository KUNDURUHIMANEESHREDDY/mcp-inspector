import { readFileSync } from 'node:fs';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

const schema = JSON.parse(readFileSync(
  new URL('../../schemas/proofline-evidence-v1.schema.json', import.meta.url),
  'utf8',
));

const ajv = new Ajv({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);

/**
 * Validate an untrusted Proofline evidence envelope.
 *
 * Validation establishes shape only. It does not authenticate the source,
 * verify artifact contents, or authorize a record to affect a verdict.
 */
export function validateProoflineEvidence(record) {
  const valid = validate(record);
  return {
    valid: Boolean(valid),
    errors: valid ? [] : (validate.errors ?? []).map((error) => ({
      path: error.instancePath,
      keyword: error.keyword,
      message: error.message ?? 'is invalid',
    })),
  };
}
