/**
 * Observes newline-delimited JSON-RPC frames on a side channel. The proxy
 * forwards each original Buffer unchanged; inspection never re-serializes it.
 */
export class LineFramer {
  constructor({ maxFrameBytes = 16 * 1024 * 1024, onFrame, onOversize = () => {} } = {}) {
    if (!Number.isSafeInteger(maxFrameBytes) || maxFrameBytes < 1024) {
      throw new TypeError('maxFrameBytes must be an integer >= 1024');
    }
    if (typeof onFrame !== 'function') throw new TypeError('onFrame callback is required');
    this.maxFrameBytes = maxFrameBytes;
    this.onFrame = onFrame;
    this.onOversize = onOversize;
    this.parts = [];
    this.size = 0;
    this.discarding = false;
  }

  push(chunk) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    let offset = 0;
    while (offset < bytes.length) {
      const newline = bytes.indexOf(0x0a, offset);
      const end = newline === -1 ? bytes.length : newline;
      const part = bytes.subarray(offset, end);
      this.size += part.length;

      if (!this.discarding) {
        if (this.size > this.maxFrameBytes) {
          this.discarding = true;
          this.parts = [];
          try {
            this.onOversize({ maxFrameBytes: this.maxFrameBytes, observedBytes: this.size });
          } catch {
            // An observer callback must never interfere with transport forwarding.
          }
        } else if (part.length > 0) {
          this.parts.push(part);
        }
      }

      if (newline !== -1) {
        if (!this.discarding) this.#emit();
        this.#reset();
      }
      offset = end + (newline === -1 ? 0 : 1);
      if (newline === -1) break;
    }
  }

  end() {
    // Some stdio servers close after their final frame without a newline.
    if (this.size > 0 && !this.discarding) this.#emit();
    this.#reset();
  }

  #emit() {
    try {
      this.onFrame(Buffer.concat(this.parts, this.size));
    } catch {
      // Inspection is best-effort. Never let a callback break transparent IO.
    }
  }

  #reset() {
    this.parts = [];
    this.size = 0;
    this.discarding = false;
  }
}

export function decodeJsonRpcFrame(frame) {
  let text = Buffer.isBuffer(frame) ? frame.toString('utf8') : String(frame);
  if (text.endsWith('\r')) text = text.slice(0, -1);
  if (text.trim().length === 0) return { ok: false, reason: 'empty' };
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, reason: 'invalid_json' };
  }
  return { ok: true, value };
}

/** MCP transports carry individual JSON-RPC messages; JSON-RPC batch arrays are unsupported. */
export function isJsonRpcMessage(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  if (value.jsonrpc !== '2.0') return false;

  if (typeof value.method === 'string' && value.method.length > 0) {
    if (Object.hasOwn(value, 'result') || Object.hasOwn(value, 'error')) return false;
    if (Object.hasOwn(value, 'id') && !isValidId(value.id)) return false;
    if (Object.hasOwn(value, 'params') && (!value.params || typeof value.params !== 'object' || Array.isArray(value.params))) return false;
    return true;
  }

  const hasResult = Object.hasOwn(value, 'result');
  const hasError = Object.hasOwn(value, 'error');
  if (hasResult === hasError) return false;
  if (hasError && !isValidError(value.error)) return false;
  // JSON-RPC permits a null ID on an error response when the request ID could
  // not be determined (for example, a parse error). It is never a valid call ID.
  if (value.id === null) return hasError;
  if (!isValidId(value.id)) return false;
  return true;
}

function isValidError(error) {
  return Boolean(error && typeof error === 'object' && !Array.isArray(error)
    && Number.isInteger(error.code) && typeof error.message === 'string');
}

function isValidId(id) {
  return typeof id === 'string' || (typeof id === 'number' && Number.isFinite(id));
}
