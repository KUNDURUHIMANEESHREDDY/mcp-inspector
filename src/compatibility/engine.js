const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validId(value, allowNull = false) {
  if (allowNull && value === null) return true;
  if (typeof value === 'string') return true;
  return typeof value === 'number' && Number.isFinite(value);
}

/**
 * Validate a JSON-RPC 2.0 envelope without interpreting MCP method semantics.
 * Extra extension fields are allowed by JSON-RPC and intentionally ignored.
 */
export function validateJsonRpcEnvelope(message) {
  const errors = [];
  if (!isRecord(message)) {
    return { valid: false, kind: 'invalid', errors: ['envelope_must_be_object'] };
  }
  if (message.jsonrpc !== '2.0') errors.push('jsonrpc_must_equal_2.0');

  const hasMethod = hasOwn(message, 'method');
  const hasId = hasOwn(message, 'id');
  const hasResult = hasOwn(message, 'result');
  const hasError = hasOwn(message, 'error');
  let kind;

  if (hasMethod) {
    kind = hasId ? 'request' : 'notification';
    if (typeof message.method !== 'string' || message.method.length === 0) errors.push('method_must_be_nonempty_string');
    if (hasId && !validId(message.id, true)) errors.push('request_id_must_be_string_number_or_null');
    if (hasResult || hasError) errors.push('request_must_not_include_result_or_error');
    if (hasOwn(message, 'params') && !isRecord(message.params) && !Array.isArray(message.params)) errors.push('params_must_be_object_or_array');
  } else {
    kind = 'response';
    if (!hasId) errors.push('response_id_is_required');
    else if (!validId(message.id, true)) errors.push('response_id_must_be_string_number_or_null');
    if (hasResult === hasError) errors.push('response_must_include_exactly_one_of_result_or_error');
    if (hasError && !isRecord(message.error)) errors.push('error_must_be_object');
    else if (hasError) {
      if (!Number.isInteger(message.error.code)) errors.push('error_code_must_be_integer');
      if (typeof message.error.message !== 'string') errors.push('error_message_must_be_string');
    }
  }
  return { valid: errors.length === 0, kind, errors };
}

export function summarizeCompatibilityResults(results) {
  const counts = { passed: 0, failed: 0, cancelled: 0 };
  for (const result of results) {
    if (result.status === 'passed') counts.passed += 1;
    else if (result.status === 'cancelled') counts.cancelled += 1;
    else counts.failed += 1;
  }
  return { ...counts, total: results.length, success: results.length > 0 && counts.failed === 0 && counts.cancelled === 0 };
}
