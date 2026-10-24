// Real MCP fixture: the official v2 SDK serves both the 2025 handshake era and
// the 2026-07-28 modern era through its stdio entry point.
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import * as z from 'zod/v4';

serveStdio(() => {
  const server = new McpServer({ name: 'mcp-inspector-test-server', version: '1.0.0' });
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
  server.registerTool(
    'concat',
    {
      description: 'Concatenate two strings; safe integration fixture.',
      inputSchema: z.object({ left: z.string(), right: z.string() }),
    },
    async ({ left, right }) => ({ content: [{ type: 'text', text: `${left}${right}` }] }),
  );
  return server;
});
