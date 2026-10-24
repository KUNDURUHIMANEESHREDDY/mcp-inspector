// Real Streamable HTTP fixture using the official MCP TypeScript SDK v2.
import { createServer } from 'node:http';
import { once } from 'node:events';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';

function buildServer() {
  const server = new McpServer(
    { name: 'mcp-inspector-http-test-server', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );
  server.registerTool(
    'echo',
    {
      description: 'Return the supplied string without side effects.',
      inputSchema: z.object({ message: z.string().min(1).max(256) }),
      outputSchema: z.object({ echo: z.string() }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async ({ message }) => ({
      content: [{ type: 'text', text: `echo:${message}` }],
      structuredContent: { echo: message },
    }),
  );
  return server;
}

/** Tiny Node adapter around the SDK's standards-based fetch handler, used only by integration tests. */
export function createSdkHttpFixtureServer() {
  const handler = createMcpHandler(buildServer);
  return createServer(async (incoming, outgoing) => {
    try {
      const url = new URL(incoming.url || '/mcp', `http://${incoming.headers.host || '127.0.0.1'}`);
      const headers = new Headers();
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (typeof value === 'string') headers.set(name, value);
        else if (Array.isArray(value)) for (const item of value) headers.append(name, item);
      }
      let body;
      if (!['GET', 'HEAD'].includes(incoming.method || 'GET')) {
        const chunks = [];
        for await (const chunk of incoming) chunks.push(chunk);
        const bytes = Buffer.concat(chunks);
        if (bytes.length) body = bytes;
      }
      const request = new Request(url, {
        method: incoming.method || 'GET',
        headers,
        ...(body ? { body, duplex: 'half' } : {}),
      });
      const response = await handler.fetch(request);
      outgoing.writeHead(response.status, Object.fromEntries(response.headers.entries()));
      if (!response.body) {
        outgoing.end();
        return;
      }
      for await (const chunk of response.body) {
        if (!outgoing.write(Buffer.from(chunk))) await once(outgoing, 'drain');
      }
      outgoing.end();
    } catch {
      if (!outgoing.headersSent) outgoing.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      outgoing.end('SDK fixture handler failed');
    }
  });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const port = Number(process.env.PORT ?? process.argv[2] ?? 0);
  const server = createSdkHttpFixtureServer();
  server.listen(port, '127.0.0.1', () => {
    const address = server.address();
    process.stderr.write(`MCP SDK HTTP fixture listening on 127.0.0.1:${address.port}\n`);
  });
  const close = () => server.close(() => process.exit(0));
  process.once('SIGINT', close);
  process.once('SIGTERM', close);
}
