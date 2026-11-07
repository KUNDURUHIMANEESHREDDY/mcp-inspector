import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { auth } from '@modelcontextprotocol/client';
import { InMemoryOAuthProvider, createOAuthContext } from '../src/compatibility/oauth-provider.js';

test('OAuth client credentials and tokens are isolated by authorization-server issuer', () => {
  const provider = new InMemoryOAuthProvider('http://127.0.0.1:8090/callback');
  const issuerA = { issuer: 'https://issuer-a.example' };
  const issuerB = { issuer: 'https://issuer-b.example' };
  provider.saveClientInformation({ client_id: 'client-a' }, issuerA);
  assert.deepEqual(provider.clientInformation(issuerA), { client_id: 'client-a' });
  assert.equal(provider.clientInformation(issuerB), undefined);
  provider.saveTokens({ access_token: 'test-token', token_type: 'Bearer' }, issuerA);
  assert.equal(provider.tokens(issuerA).access_token, 'test-token');
  assert.equal(provider.tokens(issuerB), undefined);
  assert.equal(provider.tokens().access_token, 'test-token');
  provider.saveCodeVerifier('pkce-verifier');
  assert.equal(provider.codeVerifier(), 'pkce-verifier');
  assert.notEqual(provider.state(), provider.state());
});

test('OAuth callback binds Host and state and never serves attacker-supplied callback details', async (t) => {
  const context = await createOAuthContext();
  t.after(() => context.close());
  const state = context.provider.state();
  const redirect = new URL(context.redirectUrl);
  const send = (path, host = redirect.host) => new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: '127.0.0.1',
      port: Number(redirect.port),
      path,
      method: 'GET',
      headers: { host },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end();
  });
  const waiting = context.waitForCallback({ timeoutMs: 2_000 });
  const wrongState = await send('/callback?state=wrong&code=untrusted');
  assert.equal(wrongState.status, 400);
  assert.doesNotMatch(wrongState.body, /untrusted/);
  const wrongHost = await send('/callback?state=' + state, 'attacker.invalid');
  assert.equal(wrongHost.status, 400);
  const valid = await send('/callback?state=' + encodeURIComponent(state) + '&code=authorized-code&iss=https%3A%2F%2Fissuer.example');
  assert.equal(valid.status, 200);
  assert.match(valid.body, /Authorization received/);
  const params = await waiting;
  assert.equal(params.get('code'), 'authorized-code');
  assert.equal(params.get('iss'), 'https://issuer.example');
});



test('OAuth provider validates refresh scopes before opening a callback listener', async () => {
  const invalidScopes = [
    '',
    ' ',
    ' openid',
    'openid ',
    'openid  offline_access',
    'openid\tadmin',
    'openid\r\nadmin',
    'openid"admin',
    'openid\\admin',
    'openid café',
    'x'.repeat(2049),
  ];
  for (const refreshScope of invalidScopes) {
    assert.throws(
      () => new InMemoryOAuthProvider('http://127.0.0.1:8090/callback', { refreshScope }),
      /valid RFC 6749 scope string/,
      JSON.stringify(refreshScope),
    );
    await assert.rejects(
      createOAuthContext({ refreshScope }),
      /valid RFC 6749 scope string/,
      JSON.stringify(refreshScope),
    );
  }
  const context = await createOAuthContext({ refreshScope: 'openid profile offline_access' });
  try {
    assert.equal(context.provider.scopeForRefresh(), 'openid profile offline_access');
  } finally {
    await context.close();
  }
});
test('OAuth refresh scope is absent by default and opt-in when configured', async (t) => {
  const defaultContext = await createOAuthContext();
  t.after(() => defaultContext.close());
  assert.equal(defaultContext.provider.scopeForRefresh(), undefined);

  const scopedContext = await createOAuthContext({ refreshScope: 'openid profile offline_access' });
  t.after(() => scopedContext.close());
  assert.equal(
    scopedContext.provider.scopeForRefresh({ refresh_token: 'test-refresh-token' }),
    'openid profile offline_access',
  );
});


const MOCK_ISSUER = 'https://auth.example.test';
const MOCK_RESOURCE = 'http://127.0.0.1:3000/mcp';
const MOCK_GRANTED_SCOPE = 'openid profile offline_access';

async function runMockRefresh(refreshScope) {
  const context = await createOAuthContext(
    refreshScope === undefined ? {} : { refreshScope },
  );
  const issuer = MOCK_ISSUER;
  context.provider.saveDiscoveryState({
    authorizationServerUrl: issuer,
    authorizationServerMetadata: {
      issuer,
      token_endpoint: issuer + '/token',
      token_endpoint_auth_methods_supported: ['none'],
      grant_types_supported: ['refresh_token'],
      scopes_supported: MOCK_GRANTED_SCOPE.split(' '),
    },
    resourceMetadata: {
      resource: MOCK_RESOURCE,
      authorization_servers: [issuer],
      scopes_supported: MOCK_GRANTED_SCOPE.split(' '),
    },
  });
  context.provider.saveClientInformation({
    client_id: 'mcp-inspector-refresh-test',
    token_endpoint_auth_method: 'none',
  }, { issuer });
  context.provider.saveTokens({
    access_token: 'expired-access-token',
    token_type: 'Bearer',
    refresh_token: 'test-refresh-token',
    scope: MOCK_GRANTED_SCOPE,
    issuer,
  }, { issuer });

  const requests = [];
  const fetchFn = async (input, init = {}) => {
    const url = input instanceof URL ? input : new URL(String(input));
    requests.push({
      url,
      method: init.method,
      body: new URLSearchParams(String(init.body ?? '')),
    });
    return new Response(JSON.stringify({
      access_token: 'fresh-access-token',
      token_type: 'Bearer',
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    const result = await auth(context.provider, {
      serverUrl: MOCK_RESOURCE,
      fetchFn,
    });
    return { result, requests, tokens: context.provider.tokens() };
  } finally {
    await context.close();
  }
}

test('SDK OAuth refresh sends the configured scope and preserves it when the response omits scope', async () => {
  const { result, requests, tokens } = await runMockRefresh(MOCK_GRANTED_SCOPE);
  assert.equal(result, 'AUTHORIZED');
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url.href, MOCK_ISSUER + '/token');
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].body.get('grant_type'), 'refresh_token');
  assert.equal(requests[0].body.get('refresh_token'), 'test-refresh-token');
  assert.equal(requests[0].body.get('scope'), MOCK_GRANTED_SCOPE);
  assert.equal(tokens.access_token, 'fresh-access-token');
  assert.equal(tokens.refresh_token, 'test-refresh-token');
  assert.equal(tokens.scope, MOCK_GRANTED_SCOPE);
});

test('SDK OAuth refresh omits scope by default even when stored tokens record a granted scope', async () => {
  const { result, requests, tokens } = await runMockRefresh(undefined);
  assert.equal(result, 'AUTHORIZED');
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url.href, MOCK_ISSUER + '/token');
  assert.equal(requests[0].body.get('grant_type'), 'refresh_token');
  assert.equal(requests[0].body.get('refresh_token'), 'test-refresh-token');
  assert.equal(requests[0].body.has('scope'), false);
  assert.equal(tokens.access_token, 'fresh-access-token');
  assert.equal(tokens.refresh_token, 'test-refresh-token');
});
