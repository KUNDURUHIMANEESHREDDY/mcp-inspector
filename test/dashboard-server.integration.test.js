import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { startDashboardServer } from '../src/dashboard/server.js';
import { publishDashboardEvent, resetDashboardEventStore } from '../src/dashboard/event-store.js';

function request(port, { path = '/', method = 'GET', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: '127.0.0.1',
      port,
      path,
      method,
      headers: { host: '127.0.0.1:' + port, ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });
}

test('dashboard serves its shell and read-only status API', async (t) => {
  resetDashboardEventStore();
  const dashboard = await startDashboardServer({ listen: '127.0.0.1:0', version: 'test-version' });
  const port = dashboard.server.address().port;
  t.after(() => dashboard.close());

  const page = await request(port);
  assert.equal(page.status, 200);
  assert.match(page.headers['content-security-policy'], /default-src 'self'/);
  assert.match(page.body, /MCP Inspector/);

  const stylesheet = await request(port, { path: '/styles.css' });
  assert.equal(stylesheet.status, 200);
  assert.match(stylesheet.body, /color-scheme:light/);
  assert.match(stylesheet.body, /--muted-2:#5b6575/, 'secondary labels use a readable light-theme contrast token');
  assert.match(page.body, /name="color-scheme" content="light"/);
  assert.match(page.body, /data-view="contracts"/);
  assert.match(page.body, /data-view="fuzz"/);

  const status = await request(port, { path: '/api/status' });
  assert.equal(status.status, 200);
  const data = JSON.parse(status.body);
  assert.equal(data.version, 'test-version');
  assert.equal(data.capabilities.payloadCapture, false);
  assert.equal(data.capabilities.remoteBinding, false);
});

test('dashboard streams sanitized events via its read-only API', async (t) => {
  resetDashboardEventStore();
  const dashboard = await startDashboardServer({ listen: '127.0.0.1:0' });
  const port = dashboard.server.address().port;
  t.after(() => dashboard.close());
  publishDashboardEvent({ event: 'rpc.response', level: 'info', method: 'ping', duration_ms: 5 });

  const response = await request(port, { path: '/api/events?limit=10' });
  assert.equal(response.status, 200);
  const data = JSON.parse(response.body);
  assert.equal(data.events.length, 1);
  assert.equal(data.events[0].duration_ms, 5);
  assert.equal(Object.hasOwn(data.events[0], 'arguments'), false);
});

test('dashboard rejects hostile origins, spoofed hosts, mutation methods and unknown assets', async (t) => {
  const dashboard = await startDashboardServer({ listen: '127.0.0.1:0' });
  const port = dashboard.server.address().port;
  t.after(() => dashboard.close());

  assert.equal((await request(port, { headers: { origin: 'https://attacker.example' } })).status, 403);
  assert.equal((await request(port, { headers: { host: 'localhost.attacker.invalid:' + port } })).status, 403);
  assert.equal((await request(port, { method: 'POST', path: '/api/anything' })).status, 405);
  assert.equal((await request(port, { path: '/../../package.json' })).status, 404);
});

test('dashboard listener refuses non-loopback binding', async () => {
  await assert.rejects(startDashboardServer({ listen: '0.0.0.0:9911' }), /local-only/);
});
