import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { once } from 'node:events';
import { connect as netConnect } from 'node:net';
let startHttpProxy;
let createSafeUpstreamLookup;
let isLoopbackAddress;
try {
  ({ startHttpProxy, createSafeUpstreamLookup, isLoopbackAddress } = await import('../src/proxy/http.js'));
} catch {
  // Dependency-backed HTTP integration tests run in CI after npm install.
}

test('loopback classifier handles IPv4-mapped IPv6 consistently', { skip: !isLoopbackAddress }, () => {
  assert.equal(isLoopbackAddress('127.0.0.2'), true);
  assert.equal(isLoopbackAddress('127.0.0.1%lo0'), false, 'IPv4 literals cannot carry IPv6 zone identifiers');
  assert.equal(isLoopbackAddress('127.0.0.1%25lo0'), false, 'percent-encoded IPv4 zone suffixes are not loopback');
  assert.equal(isLoopbackAddress('127.255.255.255'), true, 'the upper edge of 127.0.0.0/8 is loopback');
  assert.equal(isLoopbackAddress('126.255.255.255'), false, 'the address immediately below the loopback block is not loopback');
  assert.equal(isLoopbackAddress('128.0.0.1'), false, 'the address immediately above the loopback block is not loopback');
  assert.equal(isLoopbackAddress('::1'), true);
  assert.equal(isLoopbackAddress('[::1]'), true, 'bracketed IPv6 literals are normalized');
  assert.equal(isLoopbackAddress('::1%lo0'), true, 'IPv6 zone identifiers do not change the loopback address');
  assert.equal(isLoopbackAddress('::ffff:127.0.0.2'), true);
  assert.equal(isLoopbackAddress('::ffff:192.0.2.1'), false);
  assert.equal(isLoopbackAddress('192.0.2.1'), false);
});

test('HTTP proxy stays loopback-only by default and rejects embedded credentials', { skip: !startHttpProxy }, () => {
  assert.throws(() => startHttpProxy({ upstream: 'http://user:pass@127.0.0.1:3000' }), /Credentials in upstream URLs are not allowed/);
  assert.throws(() => startHttpProxy({ upstream: 'http://127.0.0.1:3000', listen: '0.0.0.0:9900' }), /Non-loopback binds require --allow-remote/);
});

test('HTTP proxy treats the complete IPv4 loopback range as local', { skip: !startHttpProxy }, async (t) => {
  const upstream = createServer((request, response) => {
    request.resume();
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const upstreamAddress = upstream.address();
  const proxy = startHttpProxy({
    upstream: `http://127.0.0.1:${upstreamAddress.port}`,
    listen: '127.0.0.2:0',
  });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyAddress = proxy.server.address();
  t.after(async () => {
    await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
  });

  assert.equal(proxyAddress.address, '127.0.0.2');
  const status = await new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: '127.0.0.2',
      port: proxyAddress.port,
      path: '/mcp',
      method: 'POST',
      headers: {
        host: `127.0.0.2:${proxyAddress.port}`,
        origin: 'http://127.0.0.2:3000',
        'content-type': 'application/json',
      },
    }, (response) => {
      response.resume();
      response.on('end', () => resolve(response.statusCode));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end('{"jsonrpc":"2.0","id":1,"method":"ping"}');
  });
  assert.equal(status, 200, '127.0.0.2 bind, Host and Origin must be treated as loopback');
});

test('HTTP proxy requires a strong client token and explicit origins for remote binds', { skip: !startHttpProxy }, () => {
  const previousToken = process.env.MCP_INSPECTOR_PROXY_BEARER_TOKEN;
  const previousOrigins = process.env.MCP_INSPECTOR_ALLOWED_ORIGINS;
  try {
    delete process.env.MCP_INSPECTOR_PROXY_BEARER_TOKEN;
    process.env.MCP_INSPECTOR_ALLOWED_ORIGINS = 'https://console.example';
    assert.throws(
      () => startHttpProxy({ upstream: 'http://127.0.0.1:3000', listen: '0.0.0.0:0', allowRemote: true }),
      /MCP_INSPECTOR_PROXY_BEARER_TOKEN/,
    );

    process.env.MCP_INSPECTOR_PROXY_BEARER_TOKEN = 'short';
    assert.throws(
      () => startHttpProxy({ upstream: 'http://127.0.0.1:3000', listen: '0.0.0.0:0', allowRemote: true }),
      /at least 32 characters/,
    );

    process.env.MCP_INSPECTOR_PROXY_BEARER_TOKEN = 'test-client-token-with-at-least-32-characters';
    delete process.env.MCP_INSPECTOR_ALLOWED_ORIGINS;
    assert.throws(
      () => startHttpProxy({ upstream: 'http://127.0.0.1:3000', listen: '0.0.0.0:0', allowRemote: true }),
      /MCP_INSPECTOR_ALLOWED_ORIGINS/,
    );
  } finally {
    if (previousToken === undefined) delete process.env.MCP_INSPECTOR_PROXY_BEARER_TOKEN;
    else process.env.MCP_INSPECTOR_PROXY_BEARER_TOKEN = previousToken;
    if (previousOrigins === undefined) delete process.env.MCP_INSPECTOR_ALLOWED_ORIGINS;
    else process.env.MCP_INSPECTOR_ALLOWED_ORIGINS = previousOrigins;
  }
});

test('HTTP proxy authenticates remote clients without forwarding the proxy credential upstream', { skip: !startHttpProxy }, async (t) => {
  let upstreamCalls = 0;
  let observedAuthorization;
  const upstream = createServer(async (request, response) => {
    upstreamCalls += 1;
    observedAuthorization = request.headers.authorization;
    for await (const _chunk of request) { /* Drain request bodies without logging them. */ }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"jsonrpc":"2.0","id":11,"result":{"ok":true}}');
  });

  const envNames = [
    'MCP_INSPECTOR_PROXY_BEARER_TOKEN',
    'MCP_INSPECTOR_ALLOWED_ORIGINS',
    'MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN',
    'MCP_INSPECTOR_UPSTREAM_HEADERS',
  ];
  const previousEnv = Object.fromEntries(envNames.map((name) => [name, process.env[name]]));
  const proxyToken = 'test-client-token-with-at-least-32-characters';
  let proxy;
  try {
    process.env.MCP_INSPECTOR_PROXY_BEARER_TOKEN = proxyToken;
    process.env.MCP_INSPECTOR_ALLOWED_ORIGINS = 'http://localhost:3000';
    delete process.env.MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN;
    delete process.env.MCP_INSPECTOR_UPSTREAM_HEADERS;

    upstream.listen(0, '127.0.0.1');
    await once(upstream, 'listening');
    const upstreamAddress = upstream.address();
    proxy = startHttpProxy({
      upstream: 'http://127.0.0.1:' + upstreamAddress.port,
      listen: '0.0.0.0:0',
      allowRemote: true,
    });
    if (!proxy.server.listening) await once(proxy.server, 'listening');
    const proxyAddress = proxy.server.address();

    const send = ({ method = 'POST', headers = {}, body = '{"jsonrpc":"2.0","id":11,"method":"ping"}' } = {}) => new Promise((resolve, reject) => {
      const requestHeaders = Array.isArray(headers)
        ? ['content-type', 'application/json', ...headers]
        : { 'content-type': 'application/json', ...headers };
      const request = httpRequest({
        hostname: '127.0.0.1',
        port: proxyAddress.port,
        path: '/mcp',
        method,
        headers: requestHeaders,
      }, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => resolve({
          status: response.statusCode,
          headers: response.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        }));
        response.on('error', reject);
      });
      request.on('error', reject);
      request.end(body);
    });

    const missing = await send();
    assert.equal(missing.status, 401);
    assert.equal(missing.headers['www-authenticate'], 'Bearer realm="mcp-inspector"');
    assert.equal(missing.headers.connection, 'close', 'unauthenticated connections must close after the response');
    assert.equal(upstreamCalls, 0);

    const wrong = await send({ headers: { authorization: 'Bearer wrong-token' } });
    assert.equal(wrong.status, 401);
    assert.equal(wrong.headers.connection, 'close', 'invalid-token connections must close after the response');
    assert.equal(upstreamCalls, 0);

    const malformedHost = await send({
      headers: {
        authorization: 'Bearer ' + proxyToken,
        host: 'example.com/path',
      },
    });
    assert.equal(malformedHost.status, 403);
    assert.equal(upstreamCalls, 0, 'malformed Host authority must be rejected before contacting upstream');

    const duplicateAuthorization = await send({
      headers: [
        'authorization', 'Bearer ' + proxyToken,
        'authorization', 'Bearer ' + proxyToken,
      ],
    });
    assert.equal(duplicateAuthorization.status, 400);
    assert.equal(upstreamCalls, 0, 'duplicate Authorization fields must be rejected before contacting upstream');

    for (const invalidDnsHost of [
      'bad..example',
      'bad-.example',
      'bad.-example',
      `${'a'.repeat(64)}.example`,
    ]) {
      const rejected = await send({
        headers: { authorization: 'Bearer ' + proxyToken, host: invalidDnsHost },
      });
      assert.equal(rejected.status, 403, `invalid DNS Host must be rejected: ${invalidDnsHost}`);
      assert.equal(upstreamCalls, 0, 'invalid DNS authorities must never reach upstream');
    }

    const preflight = await send({
      method: 'OPTIONS',
      headers: {
        origin: 'http://localhost:3000',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'authorization,content-type',
      },
      body: '',
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers['access-control-allow-origin'], 'http://localhost:3000');
    assert.equal(upstreamCalls, 0);

    const authorized = await send({ headers: { authorization: 'Bearer ' + proxyToken } });
    assert.equal(authorized.status, 200);
    assert.equal(upstreamCalls, 1);
    assert.equal(observedAuthorization, undefined, 'proxy bearer token must not be forwarded to upstream');
  } finally {
    if (proxy) await proxy.close();
    if (upstream.listening) await new Promise((resolve) => upstream.close(resolve));
    for (const name of envNames) {
      if (previousEnv[name] === undefined) delete process.env[name];
      else process.env[name] = previousEnv[name];
    }
  }
});

test('HTTP proxy throttles repeated failed remote authentication by socket peer', { skip: !startHttpProxy }, async () => {
  let upstreamCalls = 0;
  const upstream = createServer(async (request, response) => {
    upstreamCalls += 1;
    for await (const _chunk of request) { /* Drain bodies without logging them. */ }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}');
  });
  const envNames = [
    'MCP_INSPECTOR_PROXY_BEARER_TOKEN',
    'MCP_INSPECTOR_ALLOWED_ORIGINS',
    'MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN',
    'MCP_INSPECTOR_UPSTREAM_HEADERS',
    'MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS',
  ];
  const previousEnv = Object.fromEntries(envNames.map((name) => [name, process.env[name]]));
  const proxyToken = 'test-client-token-with-at-least-32-characters';
  let proxy;
  try {
    process.env.MCP_INSPECTOR_PROXY_BEARER_TOKEN = proxyToken;
    process.env.MCP_INSPECTOR_ALLOWED_ORIGINS = 'https://console.example';
    delete process.env.MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN;
    delete process.env.MCP_INSPECTOR_UPSTREAM_HEADERS;
    delete process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS;

    upstream.listen(0, '127.0.0.1');
    await once(upstream, 'listening');
    const upstreamAddress = upstream.address();
    proxy = startHttpProxy({
      upstream: 'http://127.0.0.1:' + upstreamAddress.port,
      listen: '0.0.0.0:0',
      allowRemote: true,
    });
    if (!proxy.server.listening) await once(proxy.server, 'listening');
    const proxyAddress = proxy.server.address();

    const send = (authorization, forwardedFor) => new Promise((resolve, reject) => {
      const headers = { 'content-type': 'application/json' };
      if (authorization !== undefined) headers.authorization = authorization;
      if (forwardedFor) headers['x-forwarded-for'] = forwardedFor;
      const request = httpRequest({
        hostname: '127.0.0.1',
        port: proxyAddress.port,
        path: '/mcp',
        method: 'POST',
        headers,
      }, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => resolve({
          status: response.statusCode,
          headers: response.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        }));
        response.on('error', reject);
      });
      request.on('error', reject);
      request.end('{"jsonrpc":"2.0","id":1,"method":"ping"}');
    });

    for (let i = 0; i < 10; i += 1) {
      const rejected = await send('Bearer invalid-token', '203.0.113.' + (i + 1));
      assert.equal(rejected.status, 401, 'the first ten failures retain the normal bearer challenge');
    }
    const limited = await send('Bearer invalid-token', '198.51.100.99');
    assert.equal(limited.status, 429);
    assert.match(limited.headers['retry-after'], /^\d+$/);
    assert.equal(limited.headers.connection, 'close', 'rate-limited connections must close after the response');
    assert.equal(upstreamCalls, 0, 'invalid credentials must never reach the upstream');

    const authorized = await send('Bearer ' + proxyToken);
    assert.equal(authorized.status, 200, 'valid credentials must continue to work after failed attempts');
    assert.equal(upstreamCalls, 1);
  } finally {
    if (proxy) await proxy.close();
    if (upstream.listening) await new Promise((resolve) => upstream.close(resolve));
    for (const name of envNames) {
      if (previousEnv[name] === undefined) delete process.env[name];
      else process.env[name] = previousEnv[name];
    }
  }
});

test('HTTP proxy rejects empty entries in the upstream host allowlist', { skip: !startHttpProxy }, async () => {
  const previous = process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS;
  let proxy;
  try {
    for (const value of ['127.0.0.1,,example.com', ',example.com', 'example.com,', ' , ']) {
      process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS = value;
      assert.throws(
        () => startHttpProxy({ upstream: 'http://127.0.0.1:3000' }),
        /MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS must not contain empty entries/,
        `reject malformed allowlist: ${JSON.stringify(value)}`,
      );
    }
    for (const value of ['[127.0.0.1', '127.0.0.1]', '[127.0.0.1]', '[example.com]', '[example.com', 'example.com]']) {
      process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS = value;
      assert.throws(
        () => startHttpProxy({ upstream: 'http://127.0.0.1:3000' }),
        /MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS must be a comma-separated exact hostname\/IP allowlist/,
        `reject malformed bracketed allowlist entry: ${JSON.stringify(value)}`,
      );
    }
    process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS = '[::1],example.com';
    proxy = startHttpProxy({ upstream: 'http://127.0.0.1:3000', listen: '127.0.0.1:0' });
    if (!proxy.server.listening) await once(proxy.server, 'listening');
  } finally {
    if (proxy) await proxy.close();
    if (previous === undefined) delete process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS;
    else process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS = previous;
  }
});

test('HTTP proxy forwards JSON and strips connection-nominated hop-by-hop headers', { skip: !startHttpProxy }, async (t) => {
  let observedHeaders;
  const upstream = createServer(async (request, response) => {
    observedHeaders = request.headers;
    for await (const _chunk of request) { /* Drain the request without logging its contents. */ }
    response.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'connection': 'close' });
    response.end('{"jsonrpc":"2.0","id":5,"result":{"ok":true}}');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const upstreamAddress = upstream.address();
  const proxy = startHttpProxy({ upstream: `http://127.0.0.1:${upstreamAddress.port}`, listen: '127.0.0.1:0' });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyAddress = proxy.server.address();
  t.after(async () => {
    await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
  });

  const received = await new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: '127.0.0.1', port: proxyAddress.port, path: '/mcp', method: 'POST',
      headers: { 'content-type': 'application/json', connection: 'keep-alive, X-Remove-Me', 'x-remove-me': 'secret-value' },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end('{"jsonrpc":"2.0","id":5,"method":"ping"}');
  });
  assert.equal(received.status, 200);
  assert.deepEqual(JSON.parse(received.body), { jsonrpc: '2.0', id: 5, result: { ok: true } });
  assert.equal(observedHeaders['x-remove-me'], undefined);
});

test('HTTP proxy forwards fragmented SSE byte-for-byte while inspecting a split UTF-8 event', async (t) => {
  const eventBytes = Buffer.from('data: {"jsonrpc":"2.0","id":8,"result":{"text":"🌍"}}\n\n');
  const emojiOffset = eventBytes.indexOf(Buffer.from('🌍'));
  const upstream = createServer(async (request, response) => {
    for await (const _chunk of request) { /* Drain request body. */ }
    response.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-cache' });
    response.write(eventBytes.subarray(0, emojiOffset + 2));
    setTimeout(() => response.end(eventBytes.subarray(emojiOffset + 2)), 5);
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const upstreamAddress = upstream.address();
  const proxy = startHttpProxy({ upstream: `http://127.0.0.1:${upstreamAddress.port}`, listen: '127.0.0.1:0' });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyAddress = proxy.server.address();
  t.after(async () => {
    await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
  });

  const body = await new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: '127.0.0.1', port: proxyAddress.port, path: '/mcp', method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks) }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end('{"jsonrpc":"2.0","id":8,"method":"ping"}');
  });
  assert.equal(body.status, 200);
  assert.deepEqual(body.body, eventBytes);
});

test('HTTP proxy blocks cross-site browser Origins and spoofed Host headers before upstream', { skip: !startHttpProxy }, async (t) => {
  let upstreamCalls = 0;
  const upstream = createServer(async (request, response) => {
    upstreamCalls += 1;
    for await (const _chunk of request) { /* Drain the request body. */ }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"jsonrpc":"2.0","id":9,"result":{"ok":true}}');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const upstreamAddress = upstream.address();
  const proxy = startHttpProxy({ upstream: `http://127.0.0.1:${upstreamAddress.port}`, listen: '127.0.0.1:0' });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyAddress = proxy.server.address();
  t.after(async () => {
    await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
  });

  const send = (headers = {}) => new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: '127.0.0.1', port: proxyAddress.port, path: '/mcp', method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end('{"jsonrpc":"2.0","id":9,"method":"ping"}');
  });

  const originRejected = await send({ origin: 'https://attacker.example' });
  assert.equal(originRejected.status, 403);
  const hostRejected = await send({ host: 'attacker.example' });
  assert.equal(hostRejected.status, 403);
  for (const malformedHost of [
    `127.0.0.1:${proxyAddress.port}?attacker.example`,
    `127.0.0.1:${proxyAddress.port}#fragment`,
    `127.0.0.1:${proxyAddress.port}%00`,
    `127.0.0.1:\\${proxyAddress.port}`,
  ]) {
    assert.equal((await send({ host: malformedHost })).status, 403, `reject malformed Host: ${malformedHost}`);
  }
  for (const host of [
    `127.0.0.1:${proxyAddress.port}?unexpected`,
    `127.0.0.1:${proxyAddress.port}#fragment`,
    `127.0.0.1:${proxyAddress.port}%2fattacker`,
    `127.1:${proxyAddress.port}`,
    `0177.0.0.1:${proxyAddress.port}`,
    `0x7f000001:${proxyAddress.port}`,
  ]) {
    const malformedHost = await send({ host });
    assert.equal(malformedHost.status, 403, `malformed Host must be rejected: ${host}`);
  }
  assert.equal(upstreamCalls, 0, 'rejected browser requests must never reach upstream');

  const localBrowser = await send({ origin: 'http://localhost:3000' });
  assert.equal(localBrowser.status, 200);
  assert.equal(upstreamCalls, 1);
});

test('HTTP proxy rejects empty entries in the browser Origin allowlist', { skip: !startHttpProxy }, () => {
  const previous = process.env.MCP_INSPECTOR_ALLOWED_ORIGINS;
  try {
    for (const value of [
      ',https://console.example',
      'https://console.example,',
      'https://console.example,,https://other.example',
    ]) {
      process.env.MCP_INSPECTOR_ALLOWED_ORIGINS = value;
      assert.throws(
        () => startHttpProxy({ upstream: 'http://127.0.0.1:3000' }),
        /MCP_INSPECTOR_ALLOWED_ORIGINS must not contain empty entries/,
        `reject malformed Origin allowlist: ${JSON.stringify(value)}`,
      );
    }
  } finally {
    if (previous === undefined) delete process.env.MCP_INSPECTOR_ALLOWED_ORIGINS;
    else process.env.MCP_INSPECTOR_ALLOWED_ORIGINS = previous;
  }
});

test('HTTP proxy enforces an explicit Origin allowlist and answers safe CORS preflights', { skip: !startHttpProxy }, async (t) => {
  let upstreamCalls = 0;
  const upstream = createServer(async (request, response) => {
    upstreamCalls += 1;
    for await (const _chunk of request) { /* Drain request body. */ }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"jsonrpc":"2.0","id":10,"result":{"ok":true}}');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const upstreamAddress = upstream.address();
  const priorOrigins = process.env.MCP_INSPECTOR_ALLOWED_ORIGINS;
  process.env.MCP_INSPECTOR_ALLOWED_ORIGINS = 'http://localhost:3000';
  const proxy = startHttpProxy({ upstream: `http://127.0.0.1:${upstreamAddress.port}`, listen: '127.0.0.1:0' });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyAddress = proxy.server.address();
  t.after(async () => {
    await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
    if (priorOrigins === undefined) delete process.env.MCP_INSPECTOR_ALLOWED_ORIGINS;
    else process.env.MCP_INSPECTOR_ALLOWED_ORIGINS = priorOrigins;
  });

  const send = ({ method = 'POST', headers = {}, body = '{"jsonrpc":"2.0","id":10,"method":"ping"}' } = {}) => new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: '127.0.0.1', port: proxyAddress.port, path: '/mcp', method,
      headers: { 'content-type': 'application/json', ...headers },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString('utf8') }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end(body);
  });

  const preflight = await send({
    method: 'OPTIONS',
    headers: {
      origin: 'http://localhost:3000',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'authorization,content-type',
    },
    body: '',
  });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers['access-control-allow-origin'], 'http://localhost:3000');
  assert.match(preflight.headers['access-control-allow-headers'], /authorization/);
  assert.equal(upstreamCalls, 0);

  const denied = await send({ headers: { origin: 'http://localhost.attacker.invalid:3000' } });
  assert.equal(denied.status, 403);
  assert.equal(upstreamCalls, 0);

  const allowed = await send({ headers: { origin: 'http://localhost:3000' } });
  assert.equal(allowed.status, 200);
  assert.equal(allowed.headers['access-control-allow-origin'], 'http://localhost:3000');
  assert.equal(upstreamCalls, 1);
});

test('HTTP proxy keeps established SSE responses alive beyond the ordinary inactivity timeout', { skip: !startHttpProxy }, async (t) => {
  const priorTimeout = process.env.MCP_INSPECTOR_UPSTREAM_TIMEOUT_MS;
  process.env.MCP_INSPECTOR_UPSTREAM_TIMEOUT_MS = '1000';
  const eventBytes = Buffer.from('data: {"jsonrpc":"2.0","id":13,"result":{"ok":true}}\n\n');
  const upstream = createServer(async (request, response) => {
    for await (const _chunk of request) { /* Drain request body. */ }
    response.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8' });
    response.write(eventBytes.subarray(0, 18));
    setTimeout(() => response.end(eventBytes.subarray(18)), 1_250);
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const upstreamAddress = upstream.address();
  const proxy = startHttpProxy({ upstream: `http://127.0.0.1:${upstreamAddress.port}`, listen: '127.0.0.1:0' });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyAddress = proxy.server.address();
  t.after(async () => {
    await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
    if (priorTimeout === undefined) delete process.env.MCP_INSPECTOR_UPSTREAM_TIMEOUT_MS;
    else process.env.MCP_INSPECTOR_UPSTREAM_TIMEOUT_MS = priorTimeout;
  });

  const result = await new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: '127.0.0.1', port: proxyAddress.port, path: '/mcp', method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks) }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end('{"jsonrpc":"2.0","id":13,"method":"ping"}');
  });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, eventBytes);
});


test('upstream DNS address policy blocks private/reserved ranges unless explicitly trusted by hostname', { skip: !startHttpProxy }, async () => {
  const { isRestrictedUpstreamAddress } = await import('../src/proxy/http.js');
  for (const address of [
    '127.0.0.1', '10.2.3.4', '169.254.4.2', '172.16.0.1', '192.168.1.4',
    '224.0.0.1', '::1', 'fc00::1', 'fe80::1', 'fe80::1%eth0', '::ffff:7f00:1',
    // IPv4 literals cannot carry IPv6 zone identifiers; malformed resolver answers fail closed.
    '127.0.0.1%lo0', '8.8.8.8%lo0', '8.8.8.8%25lo0',
    // DNS lookup answers are bare IP literals; bracketed or half-bracketed forms fail closed.
    '[8.8.8.8]', '[8.8.8.8', '8.8.8.8]', '[2606:4700:4700::1111]',
    // Equivalent expanded forms must receive the same classification.
    '0:0:0:0:0:ffff:7f00:1',
    '2001:0db8:0000:0000:0000:0000:0000:0001',
    '2001:0001:0000:0000:0000:0000:0000:0001',
    '3fff:0000:0000:0000:0000:0000:0000:0001',
    '2002:0808:0808:0000:0000:0000:0000:0001',
  ]) {
    assert.equal(isRestrictedUpstreamAddress(address), true, 'restricted: ' + address);
  }
  for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '2606:4700:4700:0000:0000:0000:0000:1111']) {
    assert.equal(isRestrictedUpstreamAddress(address), false, 'public: ' + address);
  }
});
  
test('localhost upstream DNS answers must remain inside loopback', { skip: !createSafeUpstreamLookup }, async () => {
  const loopbackAnswers = [
    { address: '127.0.0.1', family: 4 },
    { address: '::1', family: 6 },
    { address: '::ffff:127.0.0.1', family: 6 },
  ];
  const stubLookup = (answers) => (_hostname, _options, callback) => callback(null, answers);
  const resolveWith = (hostname, answers, allowlist = new Set()) => new Promise((resolve) => {
    createSafeUpstreamLookup(allowlist, stubLookup(answers))(hostname, { all: true }, (...args) => resolve(args));
  });

  // Hostname normalization must apply before the special-use exception.
  for (const hostname of ['localhost', 'LOCALHOST.']) {
    const local = await resolveWith(hostname, loopbackAnswers);
    assert.equal(local[0], null);
    assert.deepEqual(local[1], loopbackAnswers);
  }

  for (const answers of [
    [{ address: '8.8.8.8', family: 4 }],
    [{ address: '::ffff:8.8.8.8', family: 6 }],
    [{ address: '127.0.0.1', family: 4 }, { address: '8.8.8.8', family: 4 }],
    [{ address: '::1', family: 6 }, { address: '::ffff:8.8.8.8', family: 6 }],
  ]) {
    const result = await resolveWith('localhost', answers);
    assert.equal(result[0]?.code, 'ERR_MCP_INSPECTOR_UPSTREAM_ADDRESS_BLOCKED');
  }

  // Explicit operator allowlisting remains the supported way to trust a
  // private upstream hostname; the localhost exception is narrower.
  const trusted = await resolveWith('trusted.internal', [{ address: '192.168.1.10', family: 4 }], new Set(['trusted.internal']));
  assert.equal(trusted[0], null);
  assert.deepEqual(trusted[1], [{ address: '192.168.1.10', family: 4 }]);
});

test('HTTP proxy forwards validated configured upstream headers without logging their values', { skip: !startHttpProxy }, async (t) => {
  let observedHeaders;
  const upstream = createServer(async (request, response) => {
    observedHeaders = request.headers;
    for await (const _chunk of request) { /* Drain request body. */ }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"jsonrpc":"2.0","id":44,"result":{"ok":true}}');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const address = upstream.address();
  const previous = process.env.MCP_INSPECTOR_UPSTREAM_HEADERS;
  process.env.MCP_INSPECTOR_UPSTREAM_HEADERS = JSON.stringify({ 'x-api-key': 'test-only-secret', 'x-tenant': 'qa' });
  const proxy = startHttpProxy({ upstream: 'http://127.0.0.1:' + address.port, listen: '127.0.0.1:0' });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyAddress = proxy.server.address();
  t.after(async () => {
    await proxy.close();
    await new Promise((resolveClose) => upstream.close(resolveClose));
    if (previous === undefined) delete process.env.MCP_INSPECTOR_UPSTREAM_HEADERS;
    else process.env.MCP_INSPECTOR_UPSTREAM_HEADERS = previous;
  });
  const result = await new Promise((resolve, reject) => {
    const request = httpRequest({ hostname: '127.0.0.1', port: proxyAddress.port, path: '/mcp', method: 'POST', headers: { 'content-type': 'application/json' } }, (response) => {
      response.resume();
      response.on('end', () => resolve(response.statusCode));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end('{"jsonrpc":"2.0","id":44,"method":"ping"}');
  });
  assert.equal(result, 200);
  assert.equal(observedHeaders['x-api-key'], 'test-only-secret');
  assert.equal(observedHeaders['x-tenant'], 'qa');
});

test('upstream header config fails closed for unsafe or conflicting headers', { skip: !startHttpProxy }, async () => {
  const previousHeaders = process.env.MCP_INSPECTOR_UPSTREAM_HEADERS;
  const previousToken = process.env.MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN;
  try {
    process.env.MCP_INSPECTOR_UPSTREAM_HEADERS = JSON.stringify({ Host: 'attacker.invalid' });
    assert.throws(() => startHttpProxy({ upstream: 'http://127.0.0.1:3000' }), /cannot override hop-by-hop, host, or content-length/);
    process.env.MCP_INSPECTOR_UPSTREAM_HEADERS = JSON.stringify({ authorization: 'Basic abc' });
    process.env.MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN = 'secret-token';
    assert.throws(() => startHttpProxy({ upstream: 'http://127.0.0.1:3000' }), /not both/);

    delete process.env.MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN;
    process.env.MCP_INSPECTOR_UPSTREAM_HEADERS = JSON.stringify({ 'X-Api-Key': 'one', 'x-api-key': 'two' });
    assert.throws(() => startHttpProxy({ upstream: 'http://127.0.0.1:3000' }), /duplicate header names/);
    process.env.MCP_INSPECTOR_UPSTREAM_HEADERS = JSON.stringify({ 'x-api-key': 'bad\r\nx-injected: yes' });
    assert.throws(() => startHttpProxy({ upstream: 'http://127.0.0.1:3000' }), /without control line breaks/);
    process.env.MCP_INSPECTOR_UPSTREAM_HEADERS = JSON.stringify(
      Object.fromEntries(Array.from({ length: 33 }, (_, index) => [`x-header-${index}`, 'value'])),
    );
    assert.throws(() => startHttpProxy({ upstream: 'http://127.0.0.1:3000' }), /at most 32 headers/);
  } finally {
    if (previousHeaders === undefined) delete process.env.MCP_INSPECTOR_UPSTREAM_HEADERS;
    else process.env.MCP_INSPECTOR_UPSTREAM_HEADERS = previousHeaders;
    if (previousToken === undefined) delete process.env.MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN;
    else process.env.MCP_INSPECTOR_UPSTREAM_BEARER_TOKEN = previousToken;
  }
});

test('private literal upstreams require explicit exact-host allowlisting', { skip: !startHttpProxy }, async (t) => {
  const previous = process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS;
  try {
    delete process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS;
    assert.throws(
      () => startHttpProxy({ upstream: 'http://192.168.1.20:80', listen: '127.0.0.1:0' }),
      /Private or special-use IP upstreams require an exact entry/,
    );
    process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS = '192.168.1.20';
    const proxy = startHttpProxy({ upstream: 'http://192.168.1.20:80', listen: '127.0.0.1:0' });
    if (!proxy.server.listening) await once(proxy.server, 'listening');
    t.after(() => proxy.close());
  } finally {
    if (previous === undefined) delete process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS;
    else process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS = previous;
  }
});


test('HTTP proxy rejects absolute-form and non-origin request targets before upstream', { skip: !startHttpProxy }, async (t) => {
  let upstreamCalls = 0;
  const upstream = createServer(async (request, response) => {
    upstreamCalls += 1;
    request.resume();
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('upstream reached');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const upstreamAddress = upstream.address();
  const proxy = startHttpProxy({ upstream: 'http://127.0.0.1:' + upstreamAddress.port, listen: '127.0.0.1:0' });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyPort = proxy.server.address().port;
  t.after(async () => {
    await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
  });

  const sendRawTarget = (target) => new Promise((resolve, reject) => {
    const socket = netConnect(proxyPort, '127.0.0.1', () => {
      socket.write('GET ' + target + ' HTTP/1.1\\r\\nHost: 127.0.0.1:' + proxyPort + '\\r\\nConnection: close\\r\\n\\r\\n');
    });
    let response = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => { response += chunk; });
    socket.on('end', () => resolve(response));
    socket.on('error', reject);
  });

  for (const target of [
    'http://attacker.example/steal',
    '//attacker.example/steal',
    '/\\\\attacker.example/steal',
    '/mcp#fragment',
  ]) {
    const response = await sendRawTarget(target);
    assert.ok(response.startsWith('HTTP/1.1 400'), 'invalid request target must be rejected: ' + target);
  }
  assert.equal(upstreamCalls, 0, 'invalid request targets must never reach the configured upstream');
});


test('HTTP proxy rejects duplicate Host headers before contacting upstream', { skip: !startHttpProxy }, async (t) => {
  let upstreamCalls = 0;
  const upstream = createServer(async (request, response) => {
    upstreamCalls += 1;
    request.resume();
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('upstream reached');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const upstreamAddress = upstream.address();
  const proxy = startHttpProxy({
    upstream: 'http://127.0.0.1:' + upstreamAddress.port,
    listen: '127.0.0.1:0',
  });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyPort = proxy.server.address().port;
  t.after(async () => {
    await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
  });

  const body = '{"jsonrpc":"2.0","id":71,"method":"ping"}';
  const rawRequest = [
    'POST /mcp HTTP/1.1',
    'Host: 127.0.0.1:' + proxyPort,
    'Host: localhost:' + proxyPort,
    'Content-Type: application/json',
    'Content-Length: ' + Buffer.byteLength(body),
    'Connection: close',
    '',
    body,
  ].join('\r\n');

  const response = await new Promise((resolve, reject) => {
    const socket = netConnect(proxyPort, '127.0.0.1', () => socket.write(rawRequest));
    let received = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => { received += chunk; });
    socket.on('end', () => resolve(received));
    socket.on('error', reject);
  });

  assert.match(response, /^HTTP\/1\.1 4(?:00|03)\b/, 'duplicate Host must be rejected with a client error');
  assert.equal(upstreamCalls, 0, 'duplicate Host must never reach the configured upstream');
});

test('HTTP proxy bounds incomplete request-header time and keeps request-body timeout explicit', { skip: !startHttpProxy }, async (t) => {
  const proxy = startHttpProxy({ upstream: 'http://127.0.0.1:3000', listen: '127.0.0.1:0' });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  t.after(() => proxy.close());

  assert.equal(proxy.server.headersTimeout, 15_000);
  assert.equal(proxy.server.requestTimeout, 300_000);
  assert.equal(proxy.server.keepAliveTimeout, 5_000);
});

test('HTTP proxy rejects declared request bodies above the configured cap before opening upstream', { skip: !startHttpProxy }, async (t) => {
  const previousLimit = process.env.MCP_INSPECTOR_MAX_REQUEST_BYTES;
  process.env.MCP_INSPECTOR_MAX_REQUEST_BYTES = '1024';
  let upstreamCalls = 0;
  const upstream = createServer((request, response) => {
    upstreamCalls += 1;
    request.resume();
    response.writeHead(200);
    response.end('upstream reached');
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const upstreamPort = upstream.address().port;
  const proxy = startHttpProxy({ upstream: `http://127.0.0.1:${upstreamPort}`, listen: '127.0.0.1:0' });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyPort = proxy.server.address().port;
  t.after(async () => {
    await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
    if (previousLimit === undefined) delete process.env.MCP_INSPECTOR_MAX_REQUEST_BYTES;
    else process.env.MCP_INSPECTOR_MAX_REQUEST_BYTES = previousLimit;
  });

  const body = 'x'.repeat(2048);
  const result = await new Promise((resolve, reject) => {
    const request = httpRequest({
      hostname: '127.0.0.1',
      port: proxyPort,
      path: '/mcp',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': String(Buffer.byteLength(body)),
      },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8'), headers: response.headers }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end(body);
  });

  assert.equal(result.status, 413);
  assert.equal(result.body, 'Payload Too Large');
  assert.equal(result.headers.connection, 'close');
  assert.equal(upstreamCalls, 0, 'declared oversized requests must be rejected before contacting upstream');
});

test('HTTP proxy aborts chunked request bodies that cross the configured cap', { skip: !startHttpProxy }, async (t) => {
  const previousLimit = process.env.MCP_INSPECTOR_MAX_REQUEST_BYTES;
  process.env.MCP_INSPECTOR_MAX_REQUEST_BYTES = '1024';
  let upstreamCalls = 0;
  let upstreamReceivedBytes = 0;
  let resolveUpstreamAborted;
  let resolveFirstUpstreamChunk;
  const upstreamAborted = new Promise((resolve) => { resolveUpstreamAborted = resolve; });
  const firstUpstreamChunk = new Promise((resolve) => { resolveFirstUpstreamChunk = resolve; });
  const upstream = createServer((request, response) => {
    upstreamCalls += 1;
    request.on('data', (chunk) => {
      upstreamReceivedBytes += chunk.length;
      resolveFirstUpstreamChunk(true);
    });
    request.once('aborted', () => {
      resolveUpstreamAborted(true);
      response.destroy();
    });
    request.once('end', () => {
      response.writeHead(200);
      response.end('upstream reached');
    });
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const upstreamPort = upstream.address().port;
  const proxy = startHttpProxy({ upstream: `http://127.0.0.1:${upstreamPort}`, listen: '127.0.0.1:0' });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  const proxyPort = proxy.server.address().port;
  t.after(async () => {
    await proxy.close();
    await new Promise((resolve) => upstream.close(resolve));
    if (previousLimit === undefined) delete process.env.MCP_INSPECTOR_MAX_REQUEST_BYTES;
    else process.env.MCP_INSPECTOR_MAX_REQUEST_BYTES = previousLimit;
  });

  let resolveResponse;
  let rejectResponse;
  let responseReceived = false;
  const responsePromise = new Promise((resolve, reject) => {
    resolveResponse = resolve;
    rejectResponse = reject;
  });
  const request = httpRequest({
    hostname: '127.0.0.1',
    port: proxyPort,
    path: '/mcp',
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', 'transfer-encoding': 'chunked' },
  }, (response) => {
    responseReceived = true;
    const chunks = [];
    response.on('data', (chunk) => chunks.push(chunk));
    response.on('end', () => resolveResponse({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8'), headers: response.headers }));
    response.on('error', rejectResponse);
  });
  request.on('error', (error) => {
    if (!responseReceived) rejectResponse(error);
  });
  let resolveClientClosed;
  const clientClosed = new Promise((resolve) => { resolveClientClosed = resolve; });
  request.once('close', () => resolveClientClosed(true));
  request.write('a'.repeat(700));
  let firstChunkTimer;
  await Promise.race([
    firstUpstreamChunk,
    new Promise((_, reject) => { firstChunkTimer = setTimeout(() => reject(new Error('first chunk did not reach upstream')), 1000); }),
  ]).finally(() => clearTimeout(firstChunkTimer));
  request.write('b'.repeat(700));
  // Deliberately keep the request open. The proxy must close an oversized
  // stream instead of draining an attacker-controlled remainder.
  const result = await responsePromise;

  assert.equal(result.status, 413);
  assert.equal(result.body, 'Payload Too Large');
  assert.equal(result.headers.connection, 'close');
  assert.equal(upstreamCalls, 1, 'the streamed request should be terminated rather than fully forwarded');
  assert.equal(
    await Promise.race([clientClosed, new Promise((resolve) => setTimeout(() => resolve(false), 1000))]),
    true,
    'the client connection must close without waiting for the oversized request to end',
  );
  assert.equal(
    await Promise.race([upstreamAborted, new Promise((resolve) => setTimeout(() => resolve(false), 1000))]),
    true,
    'the upstream request must be aborted after the body cap is crossed',
  );
  assert.ok(
    upstreamReceivedBytes <= 1024,
    'the chunk that crosses the body cap must not be forwarded upstream',
  );
});


test('HTTP proxy rejects invalid request-body limit configuration at startup', { skip: !startHttpProxy }, () => {
  const previousLimit = process.env.MCP_INSPECTOR_MAX_REQUEST_BYTES;
  const invalidLimits = ['1023', '67108865', '', 'not-a-number'];
  try {
    for (const value of invalidLimits) {
      process.env.MCP_INSPECTOR_MAX_REQUEST_BYTES = value;
      assert.throws(
        () => startHttpProxy({ upstream: 'http://127.0.0.1:9', listen: '127.0.0.1:0' }),
        /MCP_INSPECTOR_MAX_REQUEST_BYTES must be an integer between 1024 and 67108864/,
        `invalid request body cap should fail startup: ${JSON.stringify(value)}`,
      );
    }
  } finally {
    if (previousLimit === undefined) delete process.env.MCP_INSPECTOR_MAX_REQUEST_BYTES;
    else process.env.MCP_INSPECTOR_MAX_REQUEST_BYTES = previousLimit;
  }
});

test('HTTP proxy rejects invalid frame-size configuration at startup', { skip: !startHttpProxy }, () => {
  const previous = process.env.MCP_INSPECTOR_MAX_FRAME_BYTES;
  try {
    for (const value of ['1023', '67108865', '', 'not-a-number']) {
      process.env.MCP_INSPECTOR_MAX_FRAME_BYTES = value;
      assert.throws(
        () => startHttpProxy({ upstream: 'http://127.0.0.1:9', listen: '127.0.0.1:0' }),
        /MCP_INSPECTOR_MAX_FRAME_BYTES must be an integer between 1024 and 67108864/,
        `invalid frame cap should fail proxy startup: ${JSON.stringify(value)}`,
      );
    }
  } finally {
    if (previous === undefined) delete process.env.MCP_INSPECTOR_MAX_FRAME_BYTES;
    else process.env.MCP_INSPECTOR_MAX_FRAME_BYTES = previous;
  }
});


test('HTTP proxy closes unauthenticated partial requests without draining their bodies', {
  skip: !startHttpProxy,
  timeout: 5000,
}, async (t) => {
  const envNames = [
    'MCP_INSPECTOR_PROXY_BEARER_TOKEN',
    'MCP_INSPECTOR_ALLOWED_ORIGINS',
  ];
  const previousEnv = Object.fromEntries(envNames.map((name) => [name, process.env[name]]));
  const proxyToken = 'test-client-token-with-at-least-32-characters';
  let proxy;
  let socket;
  try {
    process.env.MCP_INSPECTOR_PROXY_BEARER_TOKEN = proxyToken;
    process.env.MCP_INSPECTOR_ALLOWED_ORIGINS = 'http://localhost:3000';

    proxy = startHttpProxy({
      upstream: 'http://127.0.0.1:9',
      listen: '0.0.0.0:0',
      allowRemote: true,
    });
    if (!proxy.server.listening) await once(proxy.server, 'listening');
    const address = proxy.server.address();

    socket = netConnect(address.port, '127.0.0.1');
    const chunks = [];
    socket.on('data', (chunk) => chunks.push(chunk));
    await once(socket, 'connect');

    const closed = new Promise((resolve, reject) => {
      socket.once('close', resolve);
      socket.once('error', reject);
    });
    socket.write([
      'POST /mcp HTTP/1.1',
      `Host: 127.0.0.1:${address.port}`,
      'Content-Type: application/json',
      'Content-Length: 1048576',
      'Connection: keep-alive',
      '',
      'partial-body-that-is-never-completed',
    ].join('\r\n'));

    await closed;
    const response = Buffer.concat(chunks).toString('latin1');
    assert.ok(response.startsWith('HTTP/1.1 401 '), 'proxy must send the authentication rejection');
    assert.ok(response.toLowerCase().includes('\r\nconnection: close\r\n'), 'proxy must instruct the client to close');
    assert.ok(response.endsWith('\r\n\r\nUnauthorized'), 'proxy must flush the complete rejection body before closing');
  } finally {
    if (socket && !socket.destroyed) socket.destroy();
    if (proxy) await proxy.close();
    for (const name of envNames) {
      if (previousEnv[name] === undefined) delete process.env[name];
      else process.env[name] = previousEnv[name];
    }
  }
});


test('HTTP proxy rejects CORS preflight bodies without draining them', {
  skip: !startHttpProxy,
  timeout: 5000,
}, async (t) => {
  const envNames = [
    'MCP_INSPECTOR_PROXY_BEARER_TOKEN',
    'MCP_INSPECTOR_ALLOWED_ORIGINS',
  ];
  const previousEnv = Object.fromEntries(envNames.map((name) => [name, process.env[name]]));
  let proxy;
  let socket;
  try {
    process.env.MCP_INSPECTOR_PROXY_BEARER_TOKEN = 'test-client-token-with-at-least-32-characters';
    process.env.MCP_INSPECTOR_ALLOWED_ORIGINS = 'http://localhost:3000';
    proxy = startHttpProxy({
      upstream: 'http://127.0.0.1:9',
      listen: '0.0.0.0:0',
      allowRemote: true,
    });
    if (!proxy.server.listening) await once(proxy.server, 'listening');
    const address = proxy.server.address();

    socket = netConnect(address.port, '127.0.0.1');
    const chunks = [];
    socket.on('data', (chunk) => chunks.push(chunk));
    await once(socket, 'connect');
    const closed = new Promise((resolve, reject) => {
      socket.once('close', resolve);
      socket.once('error', reject);
    });
    socket.write([
      'OPTIONS /mcp HTTP/1.1',
      'Host: 127.0.0.1:' + address.port,
      'Origin: http://localhost:3000',
      'Access-Control-Request-Method: POST',
      'Content-Length: 1048576',
      'Connection: keep-alive',
      '',
      'partial-preflight-body-that-is-never-completed',
    ].join('\r\n'));

    await closed;
    const response = Buffer.concat(chunks).toString('latin1');
    assert.ok(response.startsWith('HTTP/1.1 400 '), 'preflight bodies must be rejected as bad requests');
    assert.ok(response.toLowerCase().includes('\r\nconnection: close\r\n'), 'rejected preflight must close the connection');
    assert.ok(response.endsWith('\r\n\r\nBad request'), 'the complete rejection body must be flushed before closing');
  } finally {
    if (socket && !socket.destroyed) socket.destroy();
    if (proxy) await proxy.close();
    for (const name of envNames) {
      if (previousEnv[name] === undefined) delete process.env[name];
      else process.env[name] = previousEnv[name];
    }
  }
});
