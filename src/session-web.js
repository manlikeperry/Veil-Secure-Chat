// The browser transport for a chat session: the same state machine as the terminal
// client, running on WebCrypto and a WebSocket, with a local gateway standing in for
// the TCP socket.
//
// Nothing here touches the DOM, and nothing here stores anything: no localStorage, no
// IndexedDB, no service worker. The static key is generated fresh for each session and
// dies with the tab, which is what "messages gone on disconnect" has to mean in a
// browser -- a persisted identity would be a file another script could read.

import { makeSessionClass } from './session-core.js';
import * as noise from './noise-web.js';
import { cryptoCapabilities, generateKeypair } from './crypto-web.js';

export const Session = makeSessionClass(noise);

function wsTransport(socket, session) {
  socket.binaryType = 'arraybuffer';
  socket.addEventListener('message', (event) => {
    // Only ArrayBuffers are ever sent; a text frame would be something else talking to
    // the gateway and is dropped rather than decoded.
    if (event.data instanceof ArrayBuffer) session.receive(new Uint8Array(event.data));
  });
  socket.addEventListener('close', () => session.onTransportClosed());
  socket.addEventListener('error', () => session.fail(new Error('the gateway connection failed')));
  return {
    send: (bytes) => {
      if (socket.readyState !== 1) throw new Error('the websocket to the gateway is gone');
      socket.send(bytes);
    },
    close: () => {
      if (socket.readyState === 1 || socket.readyState === 0) socket.close();
    },
  };
}

// `path` is relative to the page so it works on 127.0.0.1, on a port-forwarded
// localhost, and on an onion address, without the app ever configuring a host.
export function relaySocketPath(path = '/relay') {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${scheme}//${location.host}${path}`;
}

export async function openSession({
  path,
  handle,
  initiator,
  expectedPeer = null,
  staticKeypair = null,
  onSocket,
}) {
  const capabilities = await cryptoCapabilities();
  if (!capabilities.ok) {
    throw new Error(
      'this browser cannot run the handshake: ' +
        capabilities.missing.join(', ') +
        '. Use a current Firefox/Chrome over http://127.0.0.1, or Tor Browser pointed at the onion address.'
    );
  }

  const socket = new WebSocket(onSocket ?? relaySocketPath(path));
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('the gateway did not answer')), 15000);
    socket.addEventListener('open', () => {
      clearTimeout(timer);
      resolve();
    });
    socket.addEventListener('close', () => {
      clearTimeout(timer);
      reject(new Error('the gateway refused or closed the connection'));
    });
  });

  // A fresh long-term key per session: the handshake still authenticates the two peers
  // to each other for the life of the chat, and there is no key file to steal. The
  // caller may supply one it has already shown its own fingerprint from.
  const keypair = staticKeypair ?? (await generateKeypair());
  const session = new Session({ transport: null, staticKeypair: keypair, initiator, expectedPeer });
  session.transport = wsTransport(socket, session);
  session.socket = socket;
  await session.establish(handle);
  return session;
}

export { noise };
