/** Resolve references such as {"$ref":"read#/content/0/text"} from earlier successful steps. */
export function resolveWorkflowReferences(value, completedResults, stepIndices = new Map(), currentIndex = Number.MAX_SAFE_INTEGER) {
  const unresolved = [];
  let referenceCount = 0;
  const forbiddenKeys = new Set(['__proto__', 'prototype', 'constructor']);

  function resolve(current, path, depth) {
    if (depth > 40) {
      unresolved.push({ path, reason: 'maximum_reference_depth' });
      return undefined;
    }
    if (Array.isArray(current)) return current.map((entry, index) => resolve(entry, `${path}/${index}`, depth + 1));
    if (!current || typeof current !== 'object') return current;

    const keys = Object.keys(current);
    if (keys.length === 1 && keys[0] === '$ref' && typeof current.$ref === 'string') {
      referenceCount += 1;
      const hashIndex = current.$ref.indexOf('#');
      if (hashIndex < 1) {
        unresolved.push({ path, reason: 'invalid_reference_syntax' });
        return undefined;
      }
      const stepId = current.$ref.slice(0, hashIndex);
      const pointer = current.$ref.slice(hashIndex + 1);
      if (stepIndices.has(stepId) && stepIndices.get(stepId) >= currentIndex) {
        unresolved.push({ path, reason: 'reference_must_target_an_earlier_step' });
        return undefined;
      }
      if (!completedResults.has(stepId)) {
        unresolved.push({ path, reason: 'referenced_step_has_no_successful_result' });
        return undefined;
      }
      if (pointer !== '' && !pointer.startsWith('/')) {
        unresolved.push({ path, reason: 'invalid_json_pointer' });
        return undefined;
      }
      let target = completedResults.get(stepId);
      const segments = pointer === '' ? [] : pointer.slice(1).split('/').map((segment) => segment.replace(/~1/g, '/').replace(/~0/g, '~'));
      let failed = false;
      for (const segment of segments) {
        if (forbiddenKeys.has(segment) || target === null || typeof target !== 'object') {
          failed = true;
          break;
        }
        if (Array.isArray(target)) {
          if (!/^\d+$/.test(segment) || Number(segment) >= target.length) { failed = true; break; }
          target = target[Number(segment)];
        } else if (Object.hasOwn(target, segment)) {
          target = target[segment];
        } else {
          failed = true;
          break;
        }
      }
      if (failed || target === undefined) {
        unresolved.push({ path, reason: 'json_pointer_not_found' });
        return undefined;
      }
      return target;
    }

    const output = {};
    for (const [key, entry] of Object.entries(current)) {
      if (forbiddenKeys.has(key)) {
        unresolved.push({ path: `${path}/${key}`, reason: 'unsafe_object_key' });
        continue;
      }
      output[key] = resolve(entry, `${path}/${key}`, depth + 1);
    }
    return output;
  }

  return { value: resolve(value, '', 0), unresolved, referenceCount };
}

