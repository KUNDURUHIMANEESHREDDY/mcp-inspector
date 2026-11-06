import test from 'node:test';
import assert from 'node:assert/strict';
import { isLoopbackAddress, isLoopbackHostname, normalizeHostname } from '../src/network/address.js';

test('loopback address classification covers the full IPv4 range', () => {
  assert.equal(isLoopbackAddress('127.0.0.1'), true);
  assert.equal(isLoopbackAddress('127.0.0.2'), true);
  assert.equal(isLoopbackAddress('127.255.255.255'), true);
  assert.equal(isLoopbackAddress('126.255.255.255'), false);
  assert.equal(isLoopbackAddress('128.0.0.1'), false);
  assert.equal(isLoopbackAddress('192.0.2.1'), false);
});

test('loopback address classification handles IPv6 and mapped IPv4 literals', () => {
  assert.equal(isLoopbackAddress('::1'), true);
  assert.equal(isLoopbackAddress('[::1]'), true);
  assert.equal(isLoopbackAddress('::1%lo0'), true);
  assert.equal(isLoopbackAddress('::ffff:127.0.0.2'), true);
  assert.equal(isLoopbackAddress('::ffff:192.0.2.1'), false);
});

test('malformed address spellings fail closed', () => {
  for (const value of [
    '127.0.0.1%lo0',
    '127.0.0.1%25lo0',
    '[127.0.0.1]',
    '[::1',
    '::1]',
    '[127.0.0.1',
    '127.0.0.1]',
  ]) {
    assert.equal(isLoopbackAddress(value), false, value);
  }
});

test('hostname normalization and local policy are shared', () => {
  assert.equal(normalizeHostname('LOCALHOST.'), 'localhost');
  assert.equal(normalizeHostname('[::1]'), '::1');
  assert.equal(normalizeHostname('[127.0.0.1]'), '');
  assert.equal(normalizeHostname('[::1'), '');
  assert.equal(isLoopbackHostname('LOCALHOST.'), true);
  assert.equal(isLoopbackHostname('127.0.0.2'), true);
  assert.equal(isLoopbackHostname('[::1]'), true);
  assert.equal(isLoopbackHostname('192.0.2.1'), false);
});
