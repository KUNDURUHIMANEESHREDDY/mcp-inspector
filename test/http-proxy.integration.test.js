import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { once } from 'node:events';
let startHttpProxy;
try {
  ({ startHttpProxy } = await import('../src/proxy/http.js'));
} catch {
  // Dependency-backed HTTP integration tests run in CI after npm install.
}

test('HTTP proxy stays loopback-only by default and rejects embedded credentials', { skip: !startHttpProxy }, () => {
  assert.throws(() => startHttpProxy({ upstream: 'http://user:pass@127.0.0.1:3000' }), /Credentials in upstream URLs are not allowed/);
  assert.throws(() => startHttpProxy({ upstream: 'http://127.0.0.1:3000', listen: '0.0.0.0:9900' }), /Non-loopback binds require --allow-remote/);
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
  assert.equal(upstreamCalls, 0, 'rejected browser requests must never reach upstream');

  const localBrowser = await send({ origin: 'http://localhost:3000' });
  assert.equal(localBrowser.status, 200);
  assert.equal(upstreamCalls, 1);
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
