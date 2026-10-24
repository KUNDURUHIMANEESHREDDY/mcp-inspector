import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { once } from 'node:events';

export class InMemoryOAuthProvider {
  constructor(redirectUrl) {
    this.redirectUrl = redirectUrl;
    this.clientMetadata = {
      client_name: 'MCP Inspector',
      redirect_uris: [redirectUrl],
      application_type: 'native',
    };
    this.clientInformationByIssuer = new Map();
    this.storedTokens = undefined;
    this.verifier = undefined;
    this.discovery = undefined;
    this.lastState = undefined;
    this.authorizationUrl = undefined;
  }

  clientInformation(context) {
    return context?.issuer ? this.clientInformationByIssuer.get(context.issuer) : undefined;
  }

  saveClientInformation(information, context) {
    if (typeof context?.issuer !== 'string' || !context.issuer) {
      throw new Error('OAuth client information must be associated with its authorization-server issuer');
    }
    this.clientInformationByIssuer.set(context.issuer, information);
  }

  tokens(context) {
    if (!this.storedTokens) return undefined;
    if (context?.issuer && this.storedTokens.issuer && context.issuer !== this.storedTokens.issuer) return undefined;
    return this.storedTokens;
  }

  saveTokens(tokens, context) {
    const issuer = context?.issuer ?? this.storedTokens?.issuer;
    this.storedTokens = issuer ? { ...tokens, issuer } : { ...tokens };
  }

  state() {
    this.lastState = randomUUID();
    return this.lastState;
  }

  saveDiscoveryState(state) {
    this.discovery = state;
  }

  discoveryState() {
    return this.discovery;
  }

  redirectToAuthorization(authorizationUrl) {
    this.authorizationUrl = new URL(authorizationUrl);
    process.stderr.write(
      '\nMCP Inspector needs OAuth authorization. Open this URL in your browser:\n' +
      this.authorizationUrl.href +
      '\nAfter authorization, the local callback will complete the sign-in.\n',
    );
  }

  saveCodeVerifier(verifier) {
    this.verifier = verifier;
  }

  codeVerifier() {
    if (!this.verifier) throw new Error('OAuth PKCE verifier is not available');
    return this.verifier;
  }

  invalidateCredentials(scope) {
    if (scope === 'all' || scope === 'client') this.clientInformationByIssuer.clear();
    if (scope === 'all' || scope === 'tokens') this.storedTokens = undefined;
    if (scope === 'all' || scope === 'verifier') this.verifier = undefined;
    if (scope === 'all' || scope === 'discovery') this.discovery = undefined;
  }
}

/**
 * Creates a loopback-only OAuth callback handler. It rejects a callback unless
 * the host and OAuth state match exactly; callback error descriptions are never
 * rendered or logged. Tokens are kept in memory only for this CLI run.
 */
export async function createOAuthContext() {
  let provider;
  let waiting = null;
  let completedParams;
  let port = 0;
  const server = createServer((request, response) => {
    const expectedHost = '127.0.0.1:' + port;
    if (request.method !== 'GET' || request.headers.host !== expectedHost) {
      response.writeHead(400, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      response.end('Invalid OAuth callback request');
      return;
    }
    let callback;
    try { callback = new URL(request.url || '/', 'http://' + expectedHost); }
    catch {
      response.writeHead(400, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      response.end('Invalid OAuth callback request');
      return;
    }
    if (callback.pathname !== '/callback') {
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      response.end('Not found');
      return;
    }
    const state = callback.searchParams.get('state');
    if (!state || !provider?.lastState || state !== provider.lastState) {
      response.writeHead(400, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      response.end('OAuth state validation failed. Return to the terminal and retry.');
      return;
    }
    const params = new URLSearchParams(callback.searchParams);
    response.writeHead(200, {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
    });
    response.end('Authorization received. You may close this tab and return to MCP Inspector.');
    if (waiting) {
      const current = waiting;
      waiting = null;
      current.resolve(params);
    } else {
      completedParams = params;
    }
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  port = server.address().port;
  const redirectUrl = 'http://127.0.0.1:' + port + '/callback';
  provider = new InMemoryOAuthProvider(redirectUrl);

  function waitForCallback({ timeoutMs = 300_000, signal } = {}) {
    if (completedParams) {
      const params = completedParams;
      completedParams = undefined;
      return Promise.resolve(params);
    }
    if (waiting) return Promise.reject(new Error('An OAuth callback is already being awaited'));
    if (signal?.aborted) {
      const error = new Error('OAuth login cancelled');
      error.name = 'AbortError';
      return Promise.reject(error);
    }
    return new Promise((resolve, reject) => {
      let timer;
      const onAbort = () => {
        const error = new Error('OAuth login cancelled');
        error.name = 'AbortError';
        finish(error);
      };
      const finish = (error, params) => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        if (waiting === current) waiting = null;
        if (error) reject(error);
        else resolve(params);
      };
      const current = {
        resolve: (params) => finish(null, params),
        reject: (error) => finish(error),
      };
      waiting = current;
      timer = setTimeout(() => {
        const error = new Error('OAuth callback timed out');
        error.name = 'TimeoutError';
        finish(error);
      }, timeoutMs);
      timer.unref?.();
      signal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  async function close() {
    if (waiting) {
      const current = waiting;
      waiting = null;
      const error = new Error('OAuth callback listener closed');
      error.name = 'AbortError';
      current.reject(error);
    }
    await new Promise((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections?.();
    });
    provider.invalidateCredentials('all');
    completedParams = undefined;
  }

  return { provider, redirectUrl, waitForCallback, close };
}
