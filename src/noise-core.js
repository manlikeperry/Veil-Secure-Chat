// Noise_XX_25519_AESGCM_SHA256 -- handshake plus transport ratchet, as a factory
// over an injected crypto provider.
//
//   -> e
//   <- e, ee, s, se
//   -> s, es
//
// The second DH of message 2 cannot be DH(initiator_static, responder_ephemeral):
// the responder does not hold the initiator's static key until message 3. The only
// secret computable by both sides at that point is DH(responder_static,
// initiator_ephemeral). So each role's step list below names DH operations by
// (which local private key, which remote public key) and the two lists are the
// transpose of each other -- that is what makes the derived keys provably equal.
//
// Handshake messages carry an empty payload, encrypted when a key exists. Noise
// transmits no length for a handshake payload, so the payload is whatever bytes are
// left -- which is why an empty one still costs a 16-byte tag on messages 2 and 3.
// Omitting it is a common shortcut and produces a protocol that only talks to itself;
// including it is what makes the official vectors in test/vectors.test.js match.
//
// Why a factory: a browser cannot import node:crypto and WebCrypto only answers
// asynchronously, so every primitive call is awaited. Doing that once here means the
// handshake state machine exists in exactly one place, shared byte-for-byte by the
// Node client and the web client. src/noise.js binds it to node:crypto,
// src/noise-web.js binds it to WebCrypto; both get the same classes.

import {
  AEAD_TAG_LEN,
  DH_LEN,
  HASH_LEN,
  alloc,
  concat,
  equals,
  fromUtf8,
  readU16BE,
  toHex,
  writeU16BE,
} from './bytes.js';

const PROTOCOL_NAME = 'Noise_XX_25519_AESGCM_SHA256';
const REKEY_AFTER_MESSAGES = 65536;
export const MAX_TRANSPORT_PAYLOAD = 65535 - 2;

// A handshake op's contribution to the wire size of its message.
function opSize(op) {
  if (op.t === 're' || op.t === 'e') return DH_LEN;
  if (op.t === 'rs' || op.t === 's') return DH_LEN + AEAD_TAG_LEN;
  return 0;
}

// priv/pub name the local private key type and the remote public key type.
const INITIATOR_STEPS = [
  {
    direction: 'write',
    ops: [{ t: 'e' }],
  },
  {
    direction: 'read',
    ops: [
      { t: 're' },
      { t: 'dh', priv: 'e', pub: 'e' },
      { t: 'rs' },
      { t: 'dh', priv: 'e', pub: 's' },
    ],
  },
  {
    direction: 'write',
    ops: [{ t: 's' }, { t: 'dh', priv: 's', pub: 'e' }],
  },
];

const RESPONDER_STEPS = [
  {
    direction: 'read',
    ops: [{ t: 're' }],
  },
  {
    direction: 'write',
    ops: [
      { t: 'e' },
      { t: 'dh', priv: 'e', pub: 'e' },
      { t: 's' },
      { t: 'dh', priv: 's', pub: 'e' },
    ],
  },
  {
    direction: 'read',
    ops: [{ t: 'rs' }, { t: 'dh', priv: 'e', pub: 's' }],
  },
];

export function makeNoiseApi(P) {
  class SymmetricState {
    constructor(h, ck) {
      this.h = h;
      this.ck = ck;
      this.k = null;
      this.n = 0;
    }

    async mixKey(ikm) {
      const [ck, k] = await P.hkdf(this.ck, ikm);
      this.ck = ck;
      this.k = k;
      this.n = 0;
    }

    async mixHash(data) {
      this.h = await P.sha256(concat([this.h, data]));
    }

    async encryptAndHash(plaintext) {
      if (!this.k) {
        await this.mixHash(plaintext);
        return plaintext;
      }
      const ciphertext = await P.aeadEncrypt(this.k, this.n, this.h, plaintext);
      this.n += 1;
      await this.mixHash(ciphertext);
      return ciphertext;
    }

    async decryptAndHash(ciphertext) {
      let plaintext;
      if (!this.k) {
        plaintext = ciphertext;
      } else {
        plaintext = await P.aeadDecrypt(this.k, this.n, this.h, ciphertext);
        this.n += 1;
      }
      await this.mixHash(ciphertext);
      return plaintext;
    }
  }

  async function newSymmetricState(protocolName, prologue = alloc(0)) {
    // Spec 5.4.1: h starts as the zero-padded protocol name when it fits in a hash
    // block -- it is *not* compressed -- and ck is set to that same value. Then
    // MixHash(prologue) runs unconditionally, so an empty prologue still hashes h
    // once while ck keeps the raw padded name. Skipping either half is invisible to
    // a self-consistent pair: every transcript hash and derived key shifts, yet both
    // sides agree, so the handshake still "works" until official vectors are replayed.
    const encoded = fromUtf8(protocolName);
    let h;
    if (encoded.length <= HASH_LEN) {
      h = alloc(HASH_LEN);
      h.set(encoded, 0);
    } else {
      h = await P.sha256(encoded);
    }
    const state = new SymmetricState(h, h.slice());
    await state.mixHash(prologue);
    return state;
  }

  class HandshakeState {
    // Use the async factory: the symmetric state starts with a hash of the protocol
    // name, and hashing is the provider's job.
    constructor({ initiator, staticKeypair, expectedRemoteStatic = null }) {
      this.steps = initiator ? INITIATOR_STEPS : RESPONDER_STEPS;
      this.initiator = initiator;
      this.s = staticKeypair;
      this.e = null;
      this.rs = null;
      this.re = null;
      this.expectedRemoteStatic = expectedRemoteStatic;
      this.sym = null;
      this.index = 0;
    }

    static async create(options) {
      const state = new HandshakeState(options);
      state.sym = await newSymmetricState(PROTOCOL_NAME);
      return state;
    }

    get peerIdentity() {
      return this.rs;
    }

    get nextDirection() {
      return this.steps[this.index]?.direction ?? null;
    }

    // Wire size of the message at the current index, derived from the same op table
    // that writes it, so a reader can never disagree with a writer. The payload
    // rides at the end unlengthed: with no key yet it costs nothing, once MixKey has
    // run in this message it costs an AEAD tag.
    expectedMessageSize() {
      const step = this.steps[this.index];
      if (!step) throw new Error('handshake already complete');
      const tokens = step.ops.reduce((total, op) => total + opSize(op), 0);
      const keyAtPayload = step.ops.some((op) => op.t === 'dh') || this.sym.k !== null;
      return tokens + (keyAtPayload ? AEAD_TAG_LEN : 0);
    }

    get expectedReadSize() {
      const step = this.steps[this.index];
      if (!step || step.direction !== 'read') throw new Error('not expecting to read');
      return this.expectedMessageSize();
    }

    async writeMessage() {
      const step = this.steps[this.index];
      if (!step || step.direction !== 'write') {
        throw new Error('expected to read handshake message ' + (this.index + 1));
      }
      const out = [];
      for (const op of step.ops) await this._apply('write', op, out, null);
      out.push(await this.sym.encryptAndHash(alloc(0)));
      this.index += 1;
      return concat(out);
    }

    async readMessage(message) {
      const step = this.steps[this.index];
      if (!step || step.direction !== 'read') {
        throw new Error('expected to write handshake message ' + (this.index + 1));
      }
      let buf = message;
      for (const op of step.ops) {
        const size = opSize(op);
        if (buf.length < size) throw new Error('truncated handshake message ' + (this.index + 1));
        const slice = buf.subarray(0, size);
        buf = buf.subarray(size);
        await this._apply('read', op, [], slice);
      }
      const keyAtPayload = step.ops.some((op) => op.t === 'dh') || this.sym.k !== null;
      if (buf.length !== (keyAtPayload ? AEAD_TAG_LEN : 0)) {
        throw new Error('handshake message has an unexpected payload length');
      }
      // Decrypting the empty payload is not optional: its ciphertext is mixed into
      // the hash, so skipping it diverges the transcript from a peer that sent one.
      await this.sym.decryptAndHash(buf);
      this.index += 1;
      return undefined;
    }

    async _apply(mode, op, out, input) {
      switch (op.t) {
        case 'e': {
          this.e = await P.generateKeypair();
          await this.sym.mixHash(this.e.public);
          out.push(this.e.public);
          return;
        }
        case 're': {
          this.re = input.slice();
          await this.sym.mixHash(this.re);
          return;
        }
        case 's': {
          out.push(await this.sym.encryptAndHash(this.s.public));
          return;
        }
        case 'rs': {
          const remote = (await this.sym.decryptAndHash(input)).slice();
          if (remote.length !== DH_LEN) throw new Error('malformed remote static key');
          if (this.expectedRemoteStatic && !equals(this.expectedRemoteStatic, remote)) {
            throw new Error('peer key mismatch against pinned fingerprint -- possible interception');
          }
          this.rs = remote;
          return;
        }
        case 'dh': {
          const privateKey = (op.priv === 'e' ? this.e : this.s)?.private;
          const publicKey = op.pub === 'e' ? this.re : this.rs;
          if (!privateKey || !publicKey) throw new Error('DH at the wrong handshake stage');
          await this.sym.mixKey(await P.dh(privateKey, publicKey));
          return;
        }
        default:
          throw new Error('unknown handshake op ' + op.t);
      }
    }

    isFinished() {
      return this.index === this.steps.length;
    }

    // HKDF(ck, empty, 4) -> send key, receive key, and one chaining key per
    // direction for rekeying.
    async getHandshakeResults() {
      if (!this.isFinished()) throw new Error('handshake incomplete');
      const okm = await P.hkdfMulti(this.sym.ck, alloc(0), 4);
      const key = (i) => okm.subarray(i * HASH_LEN, (i + 1) * HASH_LEN);
      const [k1, k2, ck1, ck2] = [key(0), key(1), key(2), key(3)];
      return this.initiator
        ? [new CipherState(k1, ck1), new CipherState(k2, ck2)]
        : [new CipherState(k2, ck2), new CipherState(k1, ck1)];
    }

    handshakeHash() {
      return this.sym.h;
    }
  }

  class CipherState {
    constructor(key, chainingKey) {
      this.k = key;
      this.ck = chainingKey;
      this.n = 0;
    }

    async _rekeyIfNeeded() {
      if (this.n < REKEY_AFTER_MESSAGES) return;
      const [ck, k] = await P.hkdf(this.ck, this.k);
      this.ck = ck;
      this.k = k;
      this.n = 0;
    }

    async encrypt(plaintext) {
      await this._rekeyIfNeeded();
      const ciphertext = await P.aeadEncrypt(this.k, this.n, alloc(0), plaintext);
      this.n += 1;
      return ciphertext;
    }

    async decrypt(ciphertext) {
      await this._rekeyIfNeeded();
      const plaintext = await P.aeadDecrypt(this.k, this.n, alloc(0), ciphertext);
      this.n += 1;
      return plaintext;
    }
  }

  // A transport frame is an encrypted 16-bit big-endian payload length followed by
  // the encrypted payload. Both are separate AEAD calls, so one frame costs two
  // nonces and an empty frame is 18 bytes on the wire.
  async function encryptFrame(cs, plaintext) {
    if (plaintext.length > MAX_TRANSPORT_PAYLOAD) throw new Error('frame payload exceeds 65535 bytes');
    const parts = [await cs.encrypt(writeU16BE(plaintext.length))];
    if (plaintext.length > 0) parts.push(await cs.encrypt(plaintext));
    return concat(parts);
  }

  class FrameReader {
    constructor(receiveCipher) {
      this.cs = receiveCipher;
      this.buffer = alloc(0);
      // The body length is only knowable by decrypting the length field, and that
      // consumes a nonce. So the decrypted length is kept here instead of re-reading
      // the field on the next chunk: decrypting it twice would advance the nonce
      // twice and wedge the cipher state for the rest of the session.
      this.bodyLength = null;
      // Frames must be delivered strictly in order, and decryption is async, so a
      // queue is the only way a chunk that holds two frames cannot race itself.
      this.writing = Promise.resolve();
    }

    feed(chunk, onMessage) {
      this.buffer = concat([this.buffer, chunk]);
      const run = this.writing.then(() => this._drain(onMessage));
      // The internal chain must survive a failed frame, or one bad decrypt silently
      // wedges every later delivery. The caller still sees the rejection via `run`.
      this.writing = run.catch(() => {});
      return run;
    }

    async _drain(onMessage) {
      const lengthWire = 2 + AEAD_TAG_LEN;
      for (;;) {
        if (this.bodyLength === null) {
          if (this.buffer.length < lengthWire) return;
          const decrypted = await this.cs.decrypt(this.buffer.subarray(0, lengthWire));
          this.buffer = this.buffer.subarray(lengthWire);
          this.bodyLength = readU16BE(decrypted);
        }
        const bodyWire = this.bodyLength === 0 ? 0 : this.bodyLength + AEAD_TAG_LEN;
        if (this.buffer.length < bodyWire) return;
        const plaintext =
          this.bodyLength === 0 ? alloc(0) : await this.cs.decrypt(this.buffer.subarray(0, bodyWire));
        this.buffer = this.buffer.subarray(bodyWire);
        this.bodyLength = null;
        onMessage(plaintext);
      }
    }
  }

  async function fingerprint(publicKey) {
    return toHex((await P.sha256(publicKey)).subarray(0, 8));
  }

  return {
    HandshakeState,
    CipherState,
    FrameReader,
    encryptFrame,
    fingerprint,
    MAX_TRANSPORT_PAYLOAD,
    PROTOCOL_NAME,
  };
}
