// Node's crypto provider for the Noise protocol: node:crypto, zero dependencies.
//
// The interface is deliberately async and Uint8Array-only even though node:crypto is
// synchronous, because it has to be interchangeable with src/crypto-web.js -- a
// browser's WebCrypto answers nothing but promises, and there is no Buffer there.
// src/noise-core.js is written against this shape, so both builds run the identical
// state machine. See that file for the handshake itself.

import nodeCrypto from 'node:crypto';
import { AEAD_TAG_LEN, DH_LEN, HASH_LEN, concat, isZero } from './bytes.js';

const XS25519_PRIVATE_DER_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const XS25519_PUBLIC_DER_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

export { AEAD_TAG_LEN, DH_LEN, HASH_LEN };

function sha256Sync(data) {
  return nodeCrypto.createHash('sha256').update(data).digest();
}

function hkdfBytes(chainingKey, inputKeyMaterial, outputs) {
  // RFC 5869 order: HMAC(salt, ikm). Noise's HKDF(salt, ikm) passes the chaining key
  // as the *salt* and the DH result as the *input key material*, and nodeCrypto's
  // second argument is the ikm -- so the two must not be transposed. With them
  // swapped the DH output is silently discarded and every session key becomes a
  // function of public transcript data alone, which anyone on the wire can compute.
  // Pinned by the official Noise vectors in test/vectors.test.js and by
  // test/crypto-parity.test.js, which asserts the ikm argument actually matters.
  return Buffer.from(
    nodeCrypto.hkdfSync('sha256', inputKeyMaterial, chainingKey, Buffer.alloc(0), outputs * HASH_LEN)
  );
}

function importPrivate(raw) {
  return nodeCrypto.createPrivateKey({
    key: Buffer.concat([XS25519_PRIVATE_DER_PREFIX, raw]),
    format: 'der',
    type: 'pkcs8',
  });
}

function importPublic(raw) {
  return nodeCrypto.createPublicKey({
    key: Buffer.concat([XS25519_PUBLIC_DER_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

function generateKeypairSync() {
  const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('x25519');
  return {
    private: privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-DH_LEN),
    public: publicKey.export({ type: 'spki', format: 'der' }).subarray(-DH_LEN),
  };
}

function dhSync(privateKeyRaw, publicKeyRaw) {
  const secret = nodeCrypto.diffieHellman({
    privateKey: importPrivate(privateKeyRaw),
    publicKey: importPublic(publicKeyRaw),
  });
  // A co-resident peer is attacker-controlled and can force a low-order point,
  // whose shared secret is predictable. Noise mandates aborting on all-zero.
  if (isZero(secret)) {
    throw new Error('DH produced an all-zero shared secret; rejecting peer key');
  }
  return secret;
}

// Noise AESGCM nonce: four zero bytes then the 8-bit-wide nonce big-endian,
// per the AESGCM cipher suite definition. Only matters for interop with other
// Noise stacks; within this codebase encrypt and decrypt share it.
function nonceFor(n) {
  const nonce = Buffer.alloc(12);
  nonce.writeUInt32BE(Math.floor(n / 4294967296), 4);
  nonce.writeUInt32BE(n >>> 0, 8);
  return nonce;
}

export async function sha256(data) {
  return sha256Sync(data);
}

export async function hkdf(ck, inputKeyMaterial) {
  const okm = hkdfBytes(ck, inputKeyMaterial, 2);
  // Noise's MixKey: the first block is the new chaining key, the second is the
  // cipher key.
  return [okm.subarray(0, HASH_LEN), okm.subarray(HASH_LEN, 2 * HASH_LEN)];
}

export async function hkdfMulti(ck, inputKeyMaterial, outputs) {
  return hkdfBytes(ck, inputKeyMaterial, outputs);
}

export async function generateKeypair() {
  return generateKeypairSync();
}

// Recovering the public half from a stored private key, so an identity file needs
// only the secret. Also what lets a test replay a fixed ephemeral from the official
// Noise vectors.
export function publicFromPrivate(privateKeyRaw) {
  return nodeCrypto
    .createPublicKey(importPrivate(privateKeyRaw))
    .export({ type: 'spki', format: 'der' })
    .subarray(-DH_LEN);
}

export async function dh(privateKeyRaw, publicKeyRaw) {
  return dhSync(privateKeyRaw, publicKeyRaw);
}

export async function aeadEncrypt(key, n, ad, plaintext) {
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, nonceFor(n), {
    authTagLength: AEAD_TAG_LEN,
  });
  if (ad.length > 0) cipher.setAAD(ad);
  const body = cipher.update(plaintext);
  cipher.final();
  // GCM emits no padding from final(); the tag only exists on getAuthTag().
  return concat([body, cipher.getAuthTag()]);
}

export async function aeadDecrypt(key, n, ad, ciphertext) {
  if (ciphertext.length < AEAD_TAG_LEN) throw new Error('AEAD input too short');
  const body = ciphertext.subarray(0, ciphertext.length - AEAD_TAG_LEN);
  const tag = ciphertext.subarray(ciphertext.length - AEAD_TAG_LEN);
  const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', key, nonceFor(n), {
    authTagLength: AEAD_TAG_LEN,
  });
  if (ad.length > 0) decipher.setAAD(ad);
  decipher.setAuthTag(tag);
  return concat([decipher.update(body), decipher.final()]);
}

export async function randomBytes(length) {
  return nodeCrypto.randomBytes(length);
}

export function randomBytesSync(length) {
  return nodeCrypto.randomBytes(length);
}

// The two DER prefixes above are hand-written constants and a single wrong byte
// breaks every DH. Re-importing freshly exported raw keys and checking that both
// directions of X25519 agree verifies them at load time, so a bad constant fails
// loudly on import rather than mid-handshake.
{
  const a = generateKeypairSync();
  const b = generateKeypairSync();
  if (!dhSync(a.private, b.public).equals(dhSync(b.private, a.public))) {
    throw new Error('X25519 DER prefix self-check failed');
  }
}
