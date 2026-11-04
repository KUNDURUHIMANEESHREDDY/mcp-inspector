import { isIP } from 'node:net';

/**
 * Normalize a hostname without allowing malformed bracket syntax to become
 * a valid address after parsing. Brackets are accepted only around IPv6.
 */
export function normalizeHostname(host) {
  const value = String(host || '').toLowerCase();
  if (value.startsWith('[') || value.endsWith(']')) {
    if (!value.startsWith('[') || !value.endsWith(']')) return '';
    const address = value.slice(1, -1);
    return isIP(address) === 6 ? address : '';
  }
  if (value.includes('[') || value.includes(']')) return '';
  return value.replace(/\.$/, '');
}

function inIpv4Range(address, network, prefix) {
  const value = address.split('.').reduce((acc, part) => ((acc * 256) + Number(part)) >>> 0, 0);
  const base = network.split('.').reduce((acc, part) => ((acc * 256) + Number(part)) >>> 0, 0);
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) >>> 0 === (base & mask) >>> 0;
}

function ipv6ToBigInt(address) {
  let input = String(address || '').toLowerCase().split('%')[0];
  if (isIP(input) !== 6) return null;

  if (input.includes('.')) {
    const splitAt = input.lastIndexOf(':');
    const ipv4 = input.slice(splitAt + 1);
    if (isIP(ipv4) !== 4) return null;
    const octets = ipv4.split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    input = input.slice(0, splitAt + 1) + high + ':' + low;
  }

  const halves = input.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const words = [...left, ...Array(missing).fill('0'), ...right].map((word) => Number.parseInt(word, 16));
  if (words.length !== 8 || words.some((word) => !Number.isInteger(word) || word < 0 || word > 0xffff)) return null;
  return words.reduce((result, word) => (result << 16n) | BigInt(word), 0n);
}

/**
 * Return true only for syntactically valid IPv4/IPv6 loopback literals.
 * IPv4-mapped IPv6 addresses inherit the embedded IPv4 loopback policy.
 */
export function isLoopbackAddress(address) {
  const raw = normalizeHostname(address);
  const family = isIP(raw);
  if (family === 4) return inIpv4Range(raw, '127.0.0.0', 8);
  if (family === 6) {
    const clean = raw.split('%', 1)[0];
    const value = ipv6ToBigInt(clean);
    if (value === 1n) return true;
    if ((value >> 32n) === 0xffffn) {
      const embedded = Number(value & 0xffffffffn);
      const ipv4 = [
        (embedded >>> 24) & 255,
        (embedded >>> 16) & 255,
        (embedded >>> 8) & 255,
        embedded & 255,
      ].join('.');
      return inIpv4Range(ipv4, '127.0.0.0', 8);
    }
  }
  return false;
}

/** Shared hostname policy for local-only listeners, origins and credentials. */
export function isLoopbackHostname(hostname) {
  const normalized = normalizeHostname(hostname);
  return normalized === 'localhost' || isLoopbackAddress(normalized);
}
