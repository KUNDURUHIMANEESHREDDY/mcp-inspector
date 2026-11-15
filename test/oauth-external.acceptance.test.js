/**
 * External OAuth (authorization-code + PKCE) acceptance suite.
 *
 * Stands up a controllable mock authorization server and a Bearer-protected
 * MCP HTTP resource on loopback, then drives the full interactive OAuth path
 * used by `mcp-inspector compat --oauth`:
 *   discovery → authorize (PKCE) → state-bound callback → token exchange →
 *   authenticated tools/list.
 *
 * This is the production-readiness gate for "External OAuth acceptance".
 * Tokens never leave process memory; no real third-party IdP is required.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createOAuthContext } from '../src/compatibility/oauth-provider.js';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';

const supported = Number(process.versions.node.split('.')[0]) >= 22;

function b64url(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        if (!raw) return resolve({});
        if ((request.headers['content-type'] || '').includes('application/x-www-form-urlencoded')) {
          resolve(Object.fromEntries(new URLSearchParams(raw).entries()));
          return;
        }
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(error);
      }
    });
    request.on('error', reject);
  });
}

function sendJson(response, status, body) {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(payload),
  });
  response.end(payload);
}

/**
 * Minimal OAuth 2.1 authorization server supporting:
 * - Protected Resource Metadata
 * - Authorization Server Metadata
 * - authorization-code + PKCE (S256)
 * - token endpoint (authorization_code + refresh_token)
 */
function createMockAuthorizationServer() {
  const issuedCodes = new Map();
  const issuedTokens = new Map();
  const refreshTokens = new Map();
  let issuerUrl;
  let resourceUrl;

  const server = createServer(async (request, response) => {
    const host = request.headers.host || '127.0.0.1';
    const url = new URL(request.url || '/', `http://${host}`);

    try {
      if (request.method === 'GET' && url.pathname === '/.well-known/oauth-protected-resource') {
        return sendJson(response, 200, {
          resource: resourceUrl,
          authorization_servers: [issuerUrl],
          scopes_supported: ['openid', 'profile', 'offline_access'],
        });
      }

      if (request.method === 'GET' && url.pathname === '/.well-known/oauth-authorization-server') {
        return sendJson(response, 200, {
          issuer: issuerUrl,
          authorization_endpoint: `${issuerUrl}/authorize`,
          token_endpoint: `${issuerUrl}/token`,
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code', 'refresh_token'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['none'],
          scopes_supported: ['openid', 'profile', 'offline_access'],
        });
      }

      if (request.method === 'GET' && url.pathname === '/authorize') {
        const clientId = url.searchParams.get('client_id');
        const redirectUri = url.searchParams.get('redirect_uri');
        const state = url.searchParams.get('state');
        const codeChallenge = url.searchParams.get('code_challenge');
        const codeChallengeMethod = url.searchParams.get('code_challenge_method');
        const responseType = url.searchParams.get('response_type');

        if (responseType !== 'code' || !clientId || !redirectUri || !state || !codeChallenge) {
          response.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
          response.end('invalid_request');
          return;
        }
        if (codeChallengeMethod && codeChallengeMethod !== 'S256') {
          response.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
          response.end('unsupported_challenge_method');
          return;
        }

        const code = b64url(randomBytes(24));
        issuedCodes.set(code, {
          clientId,
          redirectUri,
          codeChallenge,
          codeChallengeMethod: codeChallengeMethod || 'S256',
          expiresAt: Date.now() + 60_000,
        });

        const location = new URL(redirectUri);
        location.searchParams.set('code', code);
        location.searchParams.set('state', state);
        location.searchParams.set('iss', issuerUrl);
        response.writeHead(302, { location: location.href, 'cache-control': 'no-store' });
        response.end();
        return;
      }

      if (request.method === 'POST' && url.pathname === '/token') {
        const body = await readJsonBody(request);
        if (body.grant_type === 'authorization_code') {
          const record = issuedCodes.get(body.code);
          issuedCodes.delete(body.code);
          if (!record || record.expiresAt < Date.now()) {
            return sendJson(response, 400, { error: 'invalid_grant' });
          }
          if (record.redirectUri !== body.redirect_uri) {
            return sendJson(response, 400, { error: 'invalid_grant' });
          }
          if (!body.code_verifier) {
            return sendJson(response, 400, { error: 'invalid_request' });
          }
          const expected = b64url(createHash('sha256').update(body.code_verifier).digest());
          if (expected !== record.codeChallenge) {
            return sendJson(response, 400, { error: 'invalid_grant' });
          }

          const accessToken = `access-${b64url(randomBytes(16))}`;
          const refreshToken = `refresh-${b64url(randomBytes(16))}`;
          issuedTokens.set(accessToken, { scope: 'openid profile offline_access', expiresAt: Date.now() + 300_000 });
          refreshTokens.set(refreshToken, { accessToken });
          return sendJson(response, 200, {
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: 300,
            refresh_token: refreshToken,
            scope: 'openid profile offline_access',
          });
        }

        if (body.grant_type === 'refresh_token') {
          const record = refreshTokens.get(body.refresh_token);
          if (!record) return sendJson(response, 400, { error: 'invalid_grant' });
          const accessToken = `access-${b64url(randomBytes(16))}`;
          issuedTokens.set(accessToken, { scope: 'openid profile offline_access', expiresAt: Date.now() + 300_000 });
          record.accessToken = accessToken;
          return sendJson(response, 200, {
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: 300,
            // Intentionally omit scope so the client/provider retention path is exercised.
          });
        }

        return sendJson(response, 400, { error: 'unsupported_grant_type' });
      }

      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      response.end('not found');
    } catch {
      response.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      response.end('auth server error');
    }
  });

  return {
    server,
    issuedTokens,
    async listen() {
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const { port } = server.address();
      issuerUrl = `http://127.0.0.1:${port}`;
      return issuerUrl;
    },
    setResourceUrl(url) {
      resourceUrl = url;
    },
    validateAccessToken(token) {
      const record = issuedTokens.get(token);
      return Boolean(record && record.expiresAt > Date.now());
    },
    async close() {
      await new Promise((resolveClose) => server.close(() => resolveClose()));
    },
  };
}

function createProtectedMcpResource({ authServer }) {
  const mcp = new McpServer(
    { name: 'oauth-acceptance-mcp', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );
  mcp.registerTool(
    'echo',
    {
      description: 'Echo a message; safe acceptance fixture.',
      inputSchema: z.object({ message: z.string().min(1).max(128) }),
      outputSchema: z.object({ echo: z.string() }),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
    },
    async ({ message }) => ({
      content: [{ type: 'text', text: `echo:${message}` }],
      structuredContent: { echo: message },
    }),
  );
  const handler = createMcpHandler(mcp);

  const server = createServer(async (incoming, outgoing) => {
    try {
      const host = incoming.headers.host || '127.0.0.1';
      const url = new URL(incoming.url || '/mcp', `http://${host}`);

      // Advertise protected-resource metadata from the resource origin as well.
      if (incoming.method === 'GET' && url.pathname === '/.well-known/oauth-protected-resource') {
        return sendJson(outgoing, 200, {
          resource: `http://${host}/mcp`,
          authorization_servers: [authServer.issuerSnapshot()],
          scopes_supported: ['openid', 'profile', 'offline_access'],
        });
      }

      if (!url.pathname.startsWith('/mcp')) {
        outgoing.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        outgoing.end('not found');
        return;
      }

      const authorization = incoming.headers.authorization || '';
      const match = /^Bearer\s+(.+)$/i.exec(authorization);
      if (!match || !authServer.validateAccessToken(match[1])) {
        outgoing.writeHead(401, {
          'content-type': 'application/json',
          'www-authenticate': `Bearer FAKESECRET_k1l2m3n4o5p6q7r8s9t0="http://${host}/.well-known/oauth-protected-resource"`,
          'cache-control': 'no-store',
        });
        outgoing.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }

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
      outgoing.end('resource error');
    }
  });

  return {
    server,
    async listen() {
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      const { port } = server.address();
      return `http://127.0.0.1:${port}/mcp`;
    },
    async close() {
      await new Promise((resolveClose) => server.close(() => resolveClose()));
    },
  };
}

// Small adapter so the protected resource can advertise the live issuer URL.
function attachIssuerSnapshot(authServer) {
  let issuer = null;
  const originalListen = authServer.listen.bind(authServer);
  authServer.listen = async () => {
    issuer = await originalListen();
    return issuer;
  };
  authServer.issuerSnapshot = () => issuer;
  return authServer;
}

async function completeAuthorizeRedirect(authorizationUrl) {
  // Follow the mock AS authorize redirect and return the callback URL.
  const response = await fetch(authorizationUrl, { redirect: 'manual' });
  assert.equal(response.status, 302, 'authorize endpoint must redirect with code');
  const location = response.headers.get('location');
  assert.ok(location, 'authorize redirect must include Location');
  return new URL(location);
}

test(
  'acceptance: full OAuth authorization-code + PKCE flow authenticates tools/list',
  { skip: !supported, timeout: 60_000 },
  async (t) => {
    const started = performance.now();
    const authServer = attachIssuerSnapshot(createMockAuthorizationServer());
    await authServer.listen();
    t.after(() => authServer.close());

    const resource = createProtectedMcpResource({ authServer });
    const resourceUrl = await resource.listen();
    t.after(() => resource.close());
    authServer.setResourceUrl(resourceUrl);

    const oauthContext = await createOAuthContext({
      refreshScope: 'openid profile offline_access',
    });
    t.after(() => oauthContext.close());

    // Auto-complete the browser step: when the SDK asks to open the authorize URL,
    // follow it and deliver the callback to the local listener.
    const originalRedirect = oauthContext.provider.redirectToAuthorization.bind(oauthContext.provider);
    oauthContext.provider.redirectToAuthorization = async (authorizationUrl) => {
      originalRedirect(authorizationUrl);
      const callbackUrl = await completeAuthorizeRedirect(authorizationUrl);
      // Hit the local callback listener exactly as a browser would.
      const callbackResponse = await fetch(callbackUrl.href);
      assert.equal(callbackResponse.status, 200);
      assert.match(await callbackResponse.text(), /Authorization received/);
    };

    const client = new Client(
      { name: 'mcp-inspector-oauth-acceptance', version: '1.0.0' },
      {},
    );

    const createTransport = () =>
      new StreamableHTTPClientTransport(new URL(resourceUrl), {
        authProvider: oauthContext.provider,
      });

    let transport = createTransport();
    try {
      try {
        await client.connect(transport);
      } catch (error) {
        // Expected first contact: resource is protected.
        assert.equal(error?.name, 'UnauthorizedError');
        assert.ok(oauthContext.provider.authorizationUrl, 'provider must capture authorize URL');

        const params = await oauthContext.waitForCallback({ timeoutMs: 10_000 });
        assert.equal(params.get('state'), oauthContext.provider.lastState);
        assert.ok(params.get('code'));

        await transport.finishAuth(params);
        transport = createTransport();
        await client.connect(transport);
      }

      const listed = await client.listTools();
      assert.ok(Array.isArray(listed.tools));
      assert.ok(listed.tools.some((tool) => tool.name === 'echo'));

      const response = await client.callTool({
        name: 'echo',
        arguments: { message: 'oauth-acceptance-ok' },
      });
      assert.equal(response.structuredContent?.echo, 'oauth-acceptance-ok');

      // Tokens must remain in-memory only for this process.
      const tokens = oauthContext.provider.tokens();
      assert.ok(tokens?.access_token);
      assert.match(tokens.access_token, /^access-/);
      assert.ok(tokens.refresh_token);

      const elapsed = Number((performance.now() - started).toFixed(2));
      assert.ok(elapsed < 30_000, `OAuth acceptance took too long: ${elapsed}ms`);
    } finally {
      try {
        await client.close();
      } catch {
        /* best effort */
      }
    }
  },
);

test(
  'acceptance: OAuth callback rejects state mismatch and host spoofing',
  { skip: !supported, timeout: 15_000 },
  async (t) => {
    const context = await createOAuthContext();
    t.after(() => context.close());

    const state = context.provider.state();
    const redirect = new URL(context.redirectUrl);

    const send = (path, host = redirect.host) =>
      fetch(`http://127.0.0.1:${redirect.port}${path}`, {
        headers: { host },
      });

    const wrongState = await send('/callback?state=forged&code=x');
    assert.equal(wrongState.status, 400);
    assert.doesNotMatch(await wrongState.text(), /forged|x/);

    const wrongHost = await send(
      `/callback?state=${encodeURIComponent(state)}&code=y`,
      'evil.example',
    );
    assert.equal(wrongHost.status, 400);

    const waiting = context.waitForCallback({ timeoutMs: 2_000 });
    const valid = await send(
      `/callback?state=${encodeURIComponent(state)}&code=authorized&iss=https%3A%2F%2Fissuer.example`,
    );
    assert.equal(valid.status, 200);
    const params = await waiting;
    assert.equal(params.get('code'), 'authorized');
  },
);

test(
  'acceptance: OAuth requires HTTPS for non-loopback targets in compatibility suite',
  { skip: !supported, timeout: 10_000 },
  async () => {
    const { runCompatibilitySuite } = await import('../src/compatibility/suite.js');
    await assert.rejects(
      runCompatibilitySuite({
        transports: ['http'],
        protocols: ['legacy'],
        url: 'http://example.com/mcp',
        oauth: true,
        timeoutMs: 1_000,
      }),
      /Interactive OAuth requires HTTPS for non-loopback targets/,
    );
  },
);
