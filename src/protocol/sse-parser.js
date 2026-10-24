import { StringDecoder } from 'node:string_decoder';
import { decodeJsonRpcFrame } from './framer.js';

/** Observes SSE event framing while leaving the original response stream untouched. */
export class SseObserver {
  constructor(onJsonData, { maxEventBytes = 16 * 1024 * 1024, onOversize = () => {} } = {}) {
    this.onJsonData = onJsonData;
    this.maxEventBytes = maxEventBytes;
    this.onOversize = onOversize;
    this.parts = [];
    this.size = 0;
    this.discarding = false;
    this.decoder = new StringDecoder('utf8');
  }

  push(chunk) {
    const text = Buffer.isBuffer(chunk) ? this.decoder.write(chunk) : String(chunk);
    for (const line of text.split(/(?<=\n)/)) {
      this.size += Buffer.byteLength(line);
      if (this.size > this.maxEventBytes) {
        if (!this.discarding) this.onOversize({ maxEventBytes: this.maxEventBytes });
        this.discarding = true;
        this.parts = [];
      } else if (!this.discarding) {
        this.parts.push(line);
      }
      if (line === '\n' || line === '\r\n') this.#emit();
    }
  }

  end() {
    const tail = this.decoder.end();
    if (tail) {
      this.size += Buffer.byteLength(tail);
      if (this.size <= this.maxEventBytes && !this.discarding) this.parts.push(tail);
      else if (!this.discarding) this.onOversize({ maxEventBytes: this.maxEventBytes });
      if (this.size > this.maxEventBytes) this.discarding = true;
    }
    if (this.size > 0) this.#emit();
  }

  #emit() {
    if (!this.discarding) {
      const lines = this.parts.join('').split(/\r?\n/);
      const data = lines.filter((line) => line.startsWith('data:')).map((line) => line.slice(5).replace(/^ /, '')).join('\n');
      if (data && data !== '[DONE]') this.onJsonData(Buffer.from(data, 'utf8'));
    }
    this.parts = [];
    this.size = 0;
    this.discarding = false;
  }
}

export function observeSseChunk(observer, chunk) {
  observer.push(chunk);
}
