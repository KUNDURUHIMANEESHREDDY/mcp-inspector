import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { once } from 'node:events';
import { connect as netConnect } from 'node:net';
let startHttpProxy;
let createSafeUpstreamLookup;
try {
  ({ startHttpProxy, createSafeUpstreamLookup } = await import('../src/proxy/http.js'));
} catch {
  // Dependency-backed HTTP integration tests run in CI after npm install.
}

test('HTTP proxy stays loopback-only by default and rejects embedded credentials', { skip: !startHttpProxy }, () => {
  assert.throws(() => startHttpProxy({ upstream: 'http://user:pass@127.0.0.1:3000' }), /Credentials in upstream URLs are not allowed/);
  assert.throws(() => startHttpProxy({ upstream: 'http://127.0.0.1:3000', listen: '0.0.0.0:9900' }), /Non-loopback binds require --allow-remote/);
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
    process.env.MCP_INSPECTOR_ALLOWED_UPSTREAM_HOSTS = '127.0.0.1,example.com';
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
    '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '::ffff:7f00:1',
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

  const local = await resolveWith('localhost', loopbackAnswers);
  assert.equal(local[0], null);
  assert.deepEqual(local[1], loopbackAnswers);

  for (const answers of [
    [{ address: '8.8.8.8', family: 4 }],
    [{ address: '127.0.0.1', family: 4 }, { address: '8.8.8.8', family: 4 }],
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


test('HTTP proxy bounds incomplete request-header time and keeps request-body timeout explicit', { skip: !startHttpProxy }, async (t) => {
  const proxy = startHttpProxy({ upstream: 'http://127.0.0.1:3000', listen: '127.0.0.1:0' });
  if (!proxy.server.listening) await once(proxy.server, 'listening');
  t.after(() => proxy.close());

  assert.equal(proxy.server.headersTimeout, 15_000);
  assert.equal(proxy.server.requestTimeout, 300_000);
  assert.equal(proxy.server.keepAliveTimeout, 5_000);
});
