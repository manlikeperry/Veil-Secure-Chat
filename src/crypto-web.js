// The WebCrypto provider: the same interface as src/crypto.js, answered by
// globalThis.crypto.subtle, so src/noise-core.js runs unchanged inside a browser.
//
// Uint8Array in, Uint8Array out, promises everywhere -- this is what the protocol
// core expects from any backend. Import this file only where a DOM-free module
// graph is allowed to reach the platform crypto (a page, or Node's webcrypto in
// test/crypto-parity.test.js).

import { AEAD_TAG_LEN, DH_LEN, HASH_LEN, concat, isZero } from './bytes.js';

// Same PKCS#8 wrapper the Node provider uses; WebCrypto refuses to import an X25519
// private key as raw, so the raw 32 secret bytes travel inside a PKCS#8 prefix.
const XS25519_PRIVATE_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

export { AEAD_TAG_LEN, DH_LEN, HASH_LEN };

function subtle() {
  const api = globalThis.crypto?.subtle;
  if (!api) {
    throw new Error(
      'WebCrypto is unavailable here. A page only gets crypto.subtle over https or http://127.0.0.1 -- ' +
        'open the app at 127.0.0.1 (or its .onion address in Tor Browser), not at a LAN IP over plain http.'
    );
  }
  return api;
}

// Report what this runtime can do before a handshake tries to find out the hard way.
// X25519 in WebCrypto is the youngest part of this stack and is missing from older
// Firefox builds, which is what Tor Browser is made of.
export async function cryptoCapabilities() {
  const missing = [];
  if (!globalThis.crypto?.subtle) {
    return { ok: false, missing: ['WebCrypto (insecure context: not https and not 127.0.0.1)'] };
  }
  try {
    await subtle().digest({ name: 'SHA-256' }, new Uint8Array(1));
  } catch {
    missing.push('SHA-256');
  }
  try {
    await subtle().generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } catch {
    missing.push('AES-256-GCM');
  }
  try {
    await subtle().importKey('raw', new Uint8Array(32), 'HKDF', false, ['deriveBits']);
  } catch {
    missing.push('HKDF-SHA256');
  }
  try {
    const a = await generateKeypair();
    const b = await generateKeypair();
    await dh(a.private, b.public);
  } catch {
    missing.push('X25519');
  }
  return { ok: missing.length === 0, missing };
}

const bufferOf = (result) => new Uint8Array(result);

export async function sha256(data) {
  return bufferOf(await subtle().digest({ name: 'SHA-256' }, data));
}

async function hkdfBits(chainingKey, inputKeyMaterial, outputs) {
  // RFC 5869 with salt = the Noise chaining key and ikm = the DH result, matching
  // src/crypto.js exactly. Noise's HKDF carries no info field.
  const key = await subtle().importKey('raw', inputKeyMaterial, 'HKDF', false, ['deriveBits']);
  const bits = await subtle().deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: chainingKey, info: new Uint8Array(0) },
    key,
    outputs * HASH_LEN * 8
  );
  return bufferOf(bits);
}

export async function hkdf(ck, inputKeyMaterial) {
  const okm = await hkdfBits(ck, inputKeyMaterial, 2);
  return [okm.subarray(0, HASH_LEN), okm.subarray(HASH_LEN, 2 * HASH_LEN)];
}

export async function hkdfMulti(ck, inputKeyMaterial, outputs) {
  return hkdfBits(ck, inputKeyMaterial, outputs);
}

export async function generateKeypair() {
  const pair = await subtle().generateKey({ name: 'X25519' }, true, ['deriveBits']);
  // Raw is not a legal private-key export format for X25519, so the 32 secret bytes
  // are taken out of the tail of the PKCS#8 wrapper -- the same wrapper the Node
  // provider writes around them on the way in.
  const pkcs8 = bufferOf(await subtle().exportKey('pkcs8', pair.privateKey));
  return {
    private: pkcs8.subarray(pkcs8.length - DH_LEN),
    public: bufferOf(await subtle().exportKey('raw', pair.publicKey)),
  };
}

// The algorithm-member naming for an X25519 agree is not settled across runtimes:
// browsers use `publicKey`, Node's WebCrypto insists on `public`. Try one, then the
// other, and remember which this runtime accepted rather than paying twice.
let dhMember = 'publicKey';

export async function dh(privateKeyRaw, publicKeyRaw) {
  const privateKey = await subtle().importKey(
    'pkcs8',
    concat([XS25519_PRIVATE_PKCS8_PREFIX, privateKeyRaw]),
    { name: 'X25519' },
    false,
    ['deriveBits']
  );
  const publicKey = await subtle().importKey('raw', publicKeyRaw, { name: 'X25519' }, false, []);
  const params = (member) => ({ name: 'X25519', [member]: publicKey });
  let secret;
  try {
    secret = bufferOf(await subtle().deriveBits(params(dhMember), privateKey, DH_LEN * 8));
  } catch (err) {
    if (dhMember === 'publicKey') {
      dhMember = 'public';
      secret = bufferOf(await subtle().deriveBits(params(dhMember), privateKey, DH_LEN * 8));
    } else {
      throw err;
    }
  }
  // WebCrypto already rejects a low-order point per RFC 7748, but the check is kept
  // so that both providers refuse the same input in the same way.
  if (isZero(secret)) throw new Error('DH produced an all-zero shared secret; rejecting peer key');
  return secret;
}

function nonceFor(n) {
  const nonce = new Uint8Array(12);
  nonce[4] = Math.floor(n / 4294967296) & 0xff;
  nonce[5] = Math.floor(n / 4294967296) >>> 8 & 0xff;
  nonce[6] = Math.floor(n / 4294967296) >>> 16 & 0xff;
  nonce[7] = Math.floor(n / 4294967296) >>> 24 & 0xff;
  nonce[8] = (n >>> 24) & 0xff;
  nonce[9] = (n >>> 16) & 0xff;
  nonce[10] = (n >>> 8) & 0xff;
  nonce[11] = n & 0xff;
  return nonce;
}

async function aesKey(key) {
  return subtle().importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function aeadEncrypt(key, n, ad, plaintext) {
  const params = { name: 'AES-GCM', iv: nonceFor(n), tagLength: 128 };
  if (ad.length > 0) params.additionalData = ad;
  return bufferOf(await subtle().encrypt(params, await aesKey(key), plaintext));
}

export async function aeadDecrypt(key, n, ad, ciphertext) {
  if (ciphertext.length < AEAD_TAG_LEN) throw new Error('AEAD input too short');
  const params = { name: 'AES-GCM', iv: nonceFor(n), tagLength: 128 };
  if (ad.length > 0) params.additionalData = ad;
  return bufferOf(await subtle().decrypt(params, await aesKey(key), ciphertext));
}

export async function randomBytes(length) {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}
