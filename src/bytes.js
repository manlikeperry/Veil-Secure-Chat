// Byte helpers that work identically in Node and in a browser.
//
// Nothing in this file touches Buffer, node:crypto or the DOM, because the protocol
// modules that import it are served verbatim to the browser. Buffer instances *are*
// Uint8Arrays, so a Node socket chunk can be handed straight to these helpers.

export const HASH_LEN = 32;
export const DH_LEN = 32;
export const AEAD_TAG_LEN = 16;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function alloc(length) {
  return new Uint8Array(length);
}

export function concat(chunks) {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

// Constant-time enough for key comparison: a length-only early return still reveals
// nothing an attacker does not already know, since public keys are fixed-size.
export function equals(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function isZero(a) {
  for (let i = 0; i < a.length; i += 1) if (a[i] !== 0) return false;
  return true;
}

export function toHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex) {
  if (!/^([0-9a-fA-F]{2})*$/.test(hex)) throw new Error('malformed hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function fromUtf8(text) {
  return encoder.encode(text);
}

export function toUtf8(bytes) {
  return decoder.decode(bytes);
}

export function writeU16BE(value, length = 2) {
  if (value > 0xffff) throw new Error('value does not fit in 16 bits');
  const out = new Uint8Array(length);
  out[length - 2] = value >>> 8;
  out[length - 1] = value & 0xff;
  return out;
}

export function readU16BE(bytes, offset = 0) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}
