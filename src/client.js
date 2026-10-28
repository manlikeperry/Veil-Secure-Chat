// The Node transport for a chat session: rendezvous against the relay over TCP (or
// through Tor's SOCKS proxy), then the shared Noise state machine from
// session-core.js runs on that socket. The browser uses the same state machine over a
// WebSocket; only this file differs.

import net from 'node:net';
import * as noise from './noise.js';
import { makeSessionClass } from './session-core.js';
import { makeHandle, formatInvite, parseInvite } from './relay.js';
import { connectThroughSocks5, isOnion } from './socks5.js';

export const Session = makeSessionClass(noise);

function socketTransport(socket, session) {
  socket.setNoDelay(true);
  socket.on('data', (chunk) => session.receive(chunk));
  socket.on('close', () => session.onTransportClosed());
  socket.on('end', () => session.onTransportClosed());
  socket.on('error', (err) => session.fail(err));
  return {
    send: (bytes) => {
      if (socket.destroyed || !socket.writable) throw new Error('the socket to the relay is gone');
      socket.write(bytes);
    },
    close: () => socket.destroy(),
  };
}

Session.connect = async function connect({
  host,
  port,
  handle,
  staticKeypair,
  initiator,
  expectedPeer,
  tor,
}) {
  const socket = await openSocket({ host, port, tor });
  const session = new Session({
    transport: null,
    staticKeypair,
    initiator,
    expectedPeer: expectedPeer ?? null,
  });
  // The transport needs the session to hand its inbound bytes to, so it is attached
  // after construction rather than passed in.
  session.transport = socketTransport(socket, session);
  session.socket = socket;
  await session.establish(handle);
  return session;
};

async function openSocket({ host, port, tor }) {
  // A .onion name must never be resolved or connected locally: doing so would leak
  // both the lookup and the client IP, which is the exact thing this app promises.
  if (isOnion(host) && !tor) {
    throw new Error('refusing to resolve a .onion name without a Tor SOCKS proxy (use --tor)');
  }
  if (tor) return connectThroughSocks5({ ...tor, targetHost: host, targetPort: port });
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, host);
    socket.once('error', reject);
    socket.once('connect', () => {
      socket.removeListener('error', reject);
      resolve(socket);
    });
  });
}

export { makeHandle, formatInvite, parseInvite };
