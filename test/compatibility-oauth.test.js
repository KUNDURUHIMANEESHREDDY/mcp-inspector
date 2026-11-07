import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
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
    'openid\\tadmin',
    'openid\\r\\nadmin',
    'openid"admin',
    'openid\\\\admin',
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
