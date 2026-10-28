// Stateless rendezvous relay.
//
// It knows exactly two things while running: which opaque handles have a socket
// attached, and the socket pointers. Nothing is written to disk and nothing is
// logged, because the claim "a server admin with full root cannot read your data"
// is only credible when there is no stored data and no account table to read.
//
// It is deliberately Tor-facing: binds loopback and speaks plain TCP, because
// Tor's HiddenServicePort forwards into it unchanged. The relay never learns a
// client IP -- not as policy, but as a consequence of only ever talking to tor.

import net from 'node:net';
import { randomBytes } from 'node:crypto';
import {
  PROTOCOL_VERSION,
  CMD_JOIN,
  STATUS_OK,
  STATUS_PEER_GONE,
  JOIN_HEADER_LEN,
  parseInvite,
  formatInvite,
} from './invite.js';

export { PROTOCOL_VERSION, parseInvite, formatInvite };
export const DEFAULT_PORT = 9443;

const MAX_PRE_HEADER_BYTES = 64;
// A waiting lane's peer may start sending its handshake before pairing happens.
// Bounded so an attacker who knows a handle cannot make the relay hoard memory.
const MAX_STASH_BYTES = 8192;

// The handle is a rendezvous capability, not an identity. Random per conversation,
// no key material, so an operator cannot map it to a person -- only observe that
// two lanes share it.
export function makeHandle() {
  return randomBytes(16);
}

export function createRelayServer({ idleTimeoutMs = 10 * 60 * 1000 } = {}) {
  const waiting = new Map();
  const connections = new Set();

  const server = net.createServer((socket) => {
    connections.add(socket);
    const lane = { socket, handle: null, peer: null, alive: true, timer: null, joined: false, stash: Buffer.alloc(0) };
    socket.setNoDelay(true);
    let buffer = Buffer.alloc(0);

    socket.on('error', () => close(lane));
    socket.on('end', () => close(lane));
    socket.on('close', () => close(lane));

    lane.timer = setTimeout(() => close(lane), idleTimeoutMs);

    socket.on('data', (chunk) => {
      // Paired sockets are owned by forward(); a header must never be parsed twice.
      if (lane.peer) return;

      if (lane.joined) {
        lane.stash = Buffer.concat([lane.stash, chunk]);
        if (lane.stash.length > MAX_STASH_BYTES) close(lane);
        return;
      }

      buffer = Buffer.concat([buffer, chunk]);
      // The cap is there for a lane that never finishes a header, so it must only be
      // measured against an *incomplete* one. A websocket gateway replays the page's
      // queued JOIN together with whatever followed in a single write, and reading the
      // cap as a limit on the whole chunk would drop a perfectly good rendezvous.
      if (buffer.length < JOIN_HEADER_LEN) {
        if (buffer.length > MAX_PRE_HEADER_BYTES) return close(lane);
        return;
      }

      if (buffer[0] !== PROTOCOL_VERSION || buffer[1] !== CMD_JOIN) return close(lane);

      const handle = buffer.subarray(2, JOIN_HEADER_LEN).toString('hex');
      const remainder = Buffer.from(buffer.subarray(JOIN_HEADER_LEN));
      buffer = Buffer.alloc(0);
      lane.handle = handle;
      lane.joined = true;
      lane.stash = remainder;

      const existing = waiting.get(handle);
      if (!existing) {
        waiting.set(handle, lane);
        socket.write(Buffer.from([PROTOCOL_VERSION, STATUS_OK]));
        return;
      }
      pair(existing, lane);
    });
  });

  function pair(existing, newcomer) {
    waiting.delete(existing.handle);
    existing.peer = newcomer;
    newcomer.peer = existing;
    newcomer.socket.write(Buffer.from([PROTOCOL_VERSION, STATUS_OK]));

    clearTimeout(existing.timer);
    clearTimeout(newcomer.timer);
    existing.timer = null;
    newcomer.timer = null;

    forward(existing.socket, newcomer.socket);
    forward(newcomer.socket, existing.socket);

    // Whatever each side sent before pairing completes now, delivered in order.
    if (existing.stash.length > 0) newcomer.socket.write(existing.stash);
    if (newcomer.stash.length > 0) existing.socket.write(newcomer.stash);
    existing.stash = Buffer.alloc(0);
    newcomer.stash = Buffer.alloc(0);
  }

  // Once both JOIN headers are consumed the relay never parses traffic again.
  function forward(src, dst) {
    src.on('data', (chunk) => {
      if (dst.destroyed || !dst.writable) return;
      if (!dst.write(chunk)) src.pause();
    });
    dst.on('drain', () => src.resume());
    src.on('end', () => {
      if (dst.writable) dst.end();
    });
  }

  function close(lane) {
    if (!lane.alive) return;
    lane.alive = false;
    connections.delete(lane.socket);
    if (lane.timer) clearTimeout(lane.timer);
    if (lane.handle && waiting.get(lane.handle) === lane) waiting.delete(lane.handle);

    const peer = lane.peer;
    if (peer && peer.alive) {
      peer.alive = false;
      connections.delete(peer.socket);
      if (peer.timer) clearTimeout(peer.timer);
      if (peer.handle && waiting.get(peer.handle) === peer) waiting.delete(peer.handle);
      try {
        if (peer.socket.writable) peer.socket.write(Buffer.from([PROTOCOL_VERSION, STATUS_PEER_GONE]));
      } catch {}
      peer.socket.destroy();
    }
    lane.socket.destroy();
  }

  return {
    server,
    // Ephemeral occupancy only -- a snapshot of live sockets, never a history.
    stats: () => ({ waitingLanes: waiting.size }),
    // net.Server has no closeAllConnections, so shutdown must drop live lanes by
    // hand; otherwise an open conversation keeps the process alive after close().
    close: () =>
      new Promise((resolve) => {
        for (const socket of connections) socket.destroy();
        connections.clear();
        waiting.clear();
        server.close(resolve);
      }),
  };
}

export function listen(server, port = DEFAULT_PORT, host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.removeListener('error', reject);
      resolve(server.address());
    });
  });
}
