const MAX_WORKFLOW_BYTES = 1_048_576;
const MAX_WORKFLOW_STEPS = 500;

/** Validate and bound a workflow before spawning or connecting to an MCP server. */
export function validateWorkflowInput(workflow) {
  let serialized;
  try { serialized = JSON.stringify(workflow); }
  catch { throw new Error('Workflow must be JSON-serializable'); }
  if (typeof serialized !== 'string') throw new Error('Workflow must be JSON-serializable');
  if (Buffer.byteLength(serialized, 'utf8') > MAX_WORKFLOW_BYTES) {
    throw new Error('Workflow must not exceed 1 MiB');
  }
  if (!workflow || typeof workflow !== 'object' || Array.isArray(workflow)
    || !Array.isArray(workflow.steps) || workflow.steps.length < 1 || workflow.steps.length > MAX_WORKFLOW_STEPS) {
    throw new Error('Workflow must contain between 1 and 500 steps');
  }
  if (workflow.name !== undefined && (typeof workflow.name !== 'string' || workflow.name.length > 256)) {
    throw new Error('Workflow name must be a string of at most 256 characters');
  }

  const ids = new Set();
  workflow.steps.forEach((step, index) => {
    if (!step || typeof step !== 'object' || Array.isArray(step)
      || typeof step.tool !== 'string' || !step.tool || step.tool.length > 256
      || typeof step.arguments !== 'object' || step.arguments === null || Array.isArray(step.arguments)) {
      throw new Error(`Invalid workflow step at index ${index}`);
    }
    if (step.id !== undefined && (typeof step.id !== 'string' || !step.id || step.id.length > 128)) {
      throw new Error(`Invalid workflow step id at index ${index}`);
    }
    const id = step.id ?? `step-${index + 1}`;
    if (ids.has(id)) throw new Error(`Duplicate workflow step id: ${id}`);
    ids.add(id);
  });
}
