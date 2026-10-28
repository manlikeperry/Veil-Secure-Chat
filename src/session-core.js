// The chat session state machine, shared by the terminal client and the browser.
//
//   JOIN header -> relay status -> Noise_XX -> encrypted frames, in JSON envelopes
//
// It is deliberately transport-agnostic: a host hands it an object with send() and
// close(), then pushes inbound bytes into receive(). Node wires that to a socket,
// the browser wires it to a WebSocket, and a test can wire it to a pair of arrays.
// Nothing here touches the DOM, node:net, or localStorage, because the same bytes and
// the same promise must settle in both places -- and because the promise this app
// makes is that no message is ever written to disk.

import { Emitter } from './ee.js';
import { alloc, concat, fromUtf8, toHex, toUtf8 } from './bytes.js';
import { PROTOCOL_VERSION, STATUS_OK, joinHeader } from './invite.js';

// Message types that travel inside the encrypted frame.
export const MSG_TEXT = 'text';
export const MSG_NICK = 'nick';
export const MSG_LEAVE = 'leave';

export function makeSessionClass(api) {
  return class Session extends Emitter {
    // transport: { send(bytes), close() }
    constructor({ transport, staticKeypair, initiator, expectedPeer = null }) {
      super();
      this.transport = transport;
      this.initiator = initiator;
      this.handshake = null;
      this.buffer = alloc(0);
      this.pendingRead = null;
      this.handshakeDone = false;
      this.closed = false;
      this.sendCipher = null;
      this.frames = null;
      this.peerFingerprint = null;
      this.staticKeypair = staticKeypair;
      this.expectedPeer = expectedPeer;
    }

    async establish(handle) {
      this.transport.send(joinHeader(handle));

      const status = await this.readExactly(2);
      if (status[0] !== PROTOCOL_VERSION) throw new Error('relay protocol mismatch');
      if (status[1] !== STATUS_OK) {
        throw new Error('the rendezvous is not open -- wrong or already-taken invite');
      }

      this.handshake = await api.HandshakeState.create({
        initiator: this.initiator,
        staticKeypair: this.staticKeypair,
        expectedRemoteStatic: this.expectedPeer,
      });

      while (!this.handshake.isFinished()) {
        if (this.handshake.nextDirection === 'write') {
          this.transport.send(await this.handshake.writeMessage());
        } else {
          await this.handshake.readMessage(await this.readExactly(this.handshake.expectedReadSize));
        }
      }

      const [sendCipher, receiveCipher] = await this.handshake.getHandshakeResults();
      this.sendCipher = sendCipher;
      this.frames = new api.FrameReader(receiveCipher);
      this.handshakeDone = true;
      this.peerFingerprint = await api.fingerprint(this.handshake.peerIdentity);
      // Both halves are shown side by side during the out-of-band comparison: a peer
      // that only ever sees the other's fingerprint has nothing to check its own
      // memory of against.
      this.localFingerprint = await api.fingerprint(this.staticKeypair.public);
      const info = {
        peerFingerprint: this.peerFingerprint,
        localFingerprint: this.localFingerprint,
        peerIdentity: this.handshake.peerIdentity,
        handshakeHash: toHex(this.handshake.handshakeHash()),
      };
      this.info = info;
      this.emit('ready', info);
      return info;
    }

    // Called by the host for every inbound chunk, in arrival order.
    receive(chunk) {
      if (this.closed) return;
      if (this.handshakeDone) {
        this.frames.feed(chunk, (plaintext) => this.deliver(plaintext)).catch(() => {
          this.fail(new Error('a frame failed to decrypt -- aborting the session'));
        });
        return;
      }
      this.buffer = concat([this.buffer, chunk]);
      if (this.pendingRead) {
        const resolve = this.pendingRead;
        this.pendingRead = null;
        resolve();
      }
    }

    deliver(plaintext) {
      let message;
      try {
        message = JSON.parse(toUtf8(plaintext));
      } catch {
        this.emit('warning', 'discarded a frame that was not valid JSON');
        return;
      }
      if (message.t === MSG_LEAVE) {
        this.shutdown();
        return;
      }
      this.emit('message', message);
    }

    async send(type, body) {
      if (this.closed) throw new Error('session is closed');
      if (!this.handshakeDone) throw new Error('the handshake is not finished yet');
      const frame = await api.encryptFrame(
        this.sendCipher,
        fromUtf8(JSON.stringify({ t: type, body }))
      );
      this.transport.send(frame);
    }

    readExactly(n) {
      return new Promise((resolve, reject) => {
        const take = () => {
          if (this.closed) return reject(new Error('session closed mid-read'));
          if (this.buffer.length < n) {
            this.pendingRead = take;
            return;
          }
          const out = this.buffer.subarray(0, n);
          this.buffer = this.buffer.subarray(n);
          resolve(out);
        };
        take();
      });
    }

    fail(error) {
      if (this.closed) return;
      this.emit('error', error);
      this.shutdown();
    }

    // The host calls this when the underlying transport ends. A close is not an
    // error: the peer simply left, and there is nothing on either side to resume.
    onTransportClosed() {
      this.shutdown();
    }

    shutdown() {
      if (this.closed) return;
      this.closed = true;
      // A read still waiting on the transport must be rejected, or establish() never
      // settles and the caller hangs on an already-dead connection.
      if (this.pendingRead) {
        const retry = this.pendingRead;
        this.pendingRead = null;
        retry();
      }
      this.transport.close();
      this.emit('close');
    }

    async close() {
      try {
        await this.send(MSG_LEAVE, null);
      } catch {}
      this.shutdown();
    }
  };
}
