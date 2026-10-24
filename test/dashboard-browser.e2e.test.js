import test from 'node:test';
import assert from 'node:assert/strict';
import { startDashboardServer } from '../src/dashboard/server.js';

let chromium;
try {
  ({ chromium } = await import('playwright'));
} catch (error) {
  if (process.env.MCP_INSPECTOR_REQUIRE_BROWSER_E2E === '1') throw error;
}

test('browser E2E: dashboard loads, exposes status, and keeps sensitive APIs unavailable', {
  skip: !chromium,
  timeout: 45_000,
}, async (t) => {
  const dashboard = await startDashboardServer({ listen: '127.0.0.1:0', version: '0.1.0' });
  const browser = await chromium.launch({ headless: true });
  t.after(async () => {
    await browser.close();
    await dashboard.close();
  });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  const response = await page.goto(dashboard.url, { waitUntil: 'networkidle' });
  assert.equal(response.status(), 200);
  assert.match(await page.title(), /MCP Inspector/i);
  assert.match(await page.locator('body').innerText(), /MCP Inspector/i);
  const status = await page.evaluate(async () => {
    const response = await fetch('/api/status');
    return { status: response.status, body: await response.json() };
  });
  assert.equal(status.status, 200);
  assert.equal(status.body.ok, true);
  assert.equal(status.body.capabilities.payloadCapture, false);
  assert.equal((await page.request.get(dashboard.url + '/api/commands')).status(), 404);
  assert.deepEqual(errors, []);
});
