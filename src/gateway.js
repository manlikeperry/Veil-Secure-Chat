// The web gateway: a page cannot open a TCP socket, so this is the one place where a
// browser's WebSocket is joined to the relay's byte pipe.
//
// It joins bytes and nothing else. It never parses the JOIN header, never looks at a
// Noise message, and cannot read a chat even though it is the process the user starts
// -- which is why running it on the same machine as the relay costs nothing in trust.
// What it does hold is the origin check and the file allowlist, because those are the
// two ways a local gateway gets abused by something else running in the browser.

import http from 'node:http';
import net from 'node:net';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { upgrade } from './ws.js';
import { connectThroughSocks5, isOnion } from './socks5.js';
import { createRelayServer, listen, DEFAULT_PORT as DEFAULT_RELAY_PORT } from './relay.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));

export const DEFAULT_GATEWAY_PORT = 9444;

// Every byte this server will hand out, enumerated. Nothing is read from disk by a
// path the request supplied: the URL is a key into this table or it is a 404, which
// removes directory traversal, symlink escape and "guess what filename exists" from
// the list of things a caller can do here.
const PAGES = new Map([
  ['/', { file: 'public/index.html', type: 'text/html; charset=utf-8' }],
  ['/styles.css', { file: 'public/styles.css', type: 'text/css; charset=utf-8' }],
  ['/app.js', { file: 'public/js/app.js', type: 'text/javascript; charset=utf-8' }],
]);

// The shared protocol modules, mounted flat so that a relative import inside one of
// them (`./bytes.js`) resolves the same way in the browser as it does in Node. The
// list is deliberately short: node-only files are not reachable, so `require` of a
// built-in can never be triggered by a page asking for the wrong module.
const MODULES = [
  'bytes.js',
  'ee.js',
  'invite.js',
  'noise-core.js',
  'crypto-web.js',
  'noise-web.js',
  'session-core.js',
  'session-web.js',
];
for (const name of MODULES) {
  PAGES.set(`/js/${name}`, { file: `src/${name}`, type: 'text/javascript; charset=utf-8' });
}

// The page runs entirely on the local machine and talks to no origin but its own, so
// anything else is refused at the document level rather than by trusting the app not
// to load it. ws: is plain because 127.0.0.1 is a secure context without TLS.
const CONTENT_SECURITY_POLICY =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; " +
  "img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function securityHeaders() {
  return {
    'Content-Security-Policy': CONTENT_SECURITY_POLICY,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cache-Control': 'no-store',
  };
}

// A malicious page on any other origin could otherwise open a websocket to this port
// from the victim's browser and use it as a free relay -- or worse, drive it against
// an invite of the attacker's choosing. Same-origin-only is the control; a non-browser
// client sends no Origin at all, which stays allowed.
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

// One websocket in, one TCP connection to the relay out. Bytes flow both ways in the
// order they arrive; there is no third case.
function bridge(ws, { relayHost, relayPort, tor }, onDone) {
  let relay = null;
  const queue = [];
  let queueBytes = 0;
  let torn = false;

  const stop = () => {
    if (torn) return;
    torn = true;
    if (relay) relay.destroy();
    onDone();
    // The page has to be told as well. A gateway that only drops the relay side leaves
    // the browser sitting on an open websocket whose peer will never answer, which is
    // indistinguishable in the UI from a connection that is still working.
    ws.fail('the relay connection ended');
  };

  const dial = tor
    ? connectThroughSocks5({ ...tor, targetHost: relayHost, targetPort: relayPort })
    : new Promise((resolve, reject) => {
        const socket = net.connect(relayPort, relayHost);
        socket.once('connect', () => resolve(socket));
        socket.once('error', reject);
      });

  dial.then(
    (socket) => {
      relay = socket;
      socket.on('data', (chunk) => ws.send(chunk));
      socket.on('close', stop);
      socket.on('error', stop);
      // Anything the page sent while the dial was still in flight is replayed in
      // order: the JOIN header is the first thing a session writes, and dropping it
      // would leave the lane unreachable for the life of the connection.
      for (const bytes of queue) socket.write(bytes);
      queue.length = 0;
    },
    () => {
      // The page learns the relay is unreachable from the closed socket alone. A
      // gateway that invents its own error channel would be a second protocol to
      // implement, test and trust.
      if (torn) return;
      torn = true;
      onDone();
      ws.fail();
    }
  );

  ws.onMessage = (bytes) => {
    if (torn) return;
    if (relay) {
      relay.write(bytes);
      return;
    }
    queueBytes += bytes.length;
    // A page cannot pre-buffer more than a handshake's worth of bytes legitimately;
    // this is the ceiling on what an unverified caller can make this process hold.
    if (queueBytes > 65536) {
      stop();
      ws.fail();
      return;
    }
    queue.push(bytes);
  };
  ws.onClosed = stop;
}

export function createGateway({ relayHost, relayPort, tor = null }) {
  const connections = new Set();
  const server = http.createServer(async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { ...securityHeaders(), Allow: 'GET, HEAD' });
      res.end();
      return;
    }
    const path = (req.url ?? '/').split('?')[0];
    if (path === '/info') {
      // Only what the operator already passed on the command line, and only so the
      // page can warn when an invite points somewhere else.
      res.writeHead(200, { ...securityHeaders(), 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ relay: `${relayHost}:${relayPort}`, onion: isOnion(relayHost) }));
      return;
    }
    const entry = PAGES.get(path);
    if (!entry) {
      res.writeHead(404, securityHeaders());
      res.end('not found');
      return;
    }
    try {
      const body = await readFile(ROOT + entry.file);
      res.writeHead(200, { ...securityHeaders(), 'Content-Type': entry.type });
      res.end(req.method === 'HEAD' ? undefined : body);
    } catch {
      res.writeHead(500, securityHeaders());
      res.end('the file allowlist names a file that is not on disk');
    }
  });

  server.on('upgrade', (req, socket, head) => {
    // Node stops watching a socket the moment it emits `upgrade` -- it removes its own
    // error listener because the handler now owns the connection. So a refusal has to
    // watch it too: end() delivers the 403, the caller's socket goes away, and the RST
    // that follows is an error nobody is listening for unless this line puts one here
    // first. A page that guesses the wrong origin would otherwise take the gateway down.
    if (socket.listenerCount('error') === 0) socket.on('error', () => {});
    const path = (req.url ?? '/').split('?')[0];
    if (path !== '/relay' || !originAllowed(req)) {
      socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      return;
    }
    const ws = upgrade(req, socket, head);
    if (!ws) return;
    connections.add(ws);
    bridge(ws, { relayHost, relayPort, tor }, () => connections.delete(ws));
  });

  server.on('close', () => {
    for (const ws of connections) ws.socket.destroy();
    connections.clear();
  });

  return {
    server,
    connections,
    close: () =>
      new Promise((resolve) => {
        for (const ws of connections) ws.socket.destroy();
        connections.clear();
        server.closeAllConnections?.();
        server.close(resolve);
      }),
  };
}

function relayTarget(value) {
  const match = /^([a-zA-Z0-9.-]+):(\d+)$/.exec(value ?? '');
  if (!match) throw new Error('--relay must look like host:port');
  return { relayHost: match[1], relayPort: Number(match[2]) };
}

function guardOnion(relayHost, tor) {
  if (isOnion(relayHost) && !tor) {
    throw new Error(
      `the relay ${relayHost} is a hidden service, so the gateway must reach it through Tor. ` +
        'Pass --tor 127.0.0.1:9150 (Tor Browser) or 127.0.0.1:9050 (tor daemon).'
    );
  }
}

// A port already held by something else -- usually a previous veil that is still
// running -- is the failure that stops both web commands before they begin, and the
// raw OS error does not say what to do about it.
function portBusy(err, what, where) {
  if (err?.code !== 'EADDRINUSE') return err;
  return new Error(`${what} cannot start: ${where} is already taken. Stop what holds it, or pass a different port.`);
}

export async function commandGateway(options) {
  if (!options.relay) throw new Error('gateway needs --relay host:port');
  const { relayHost, relayPort } = relayTarget(options.relay);
  const tor = options.tor ? parseTor(options.tor) : null;
  guardOnion(relayHost, tor);

  const gateway = createGateway({ relayHost, relayPort, tor });
  const host = options.host ?? '127.0.0.1';
  const address = await listen(
    gateway.server,
    options.port ?? DEFAULT_GATEWAY_PORT,
    host
  ).catch((err) => {
    throw portBusy(err, 'the page', `${host}:${options.port ?? DEFAULT_GATEWAY_PORT}`);
  });
  console.log(`web app on http://${address.address === '0.0.0.0' ? '127.0.0.1' : address.address}:${address.port}`);
  console.log(`bridging every page session to the relay at ${relayHost}:${relayPort}${tor ? ' through Tor' : ''}`);
  console.log('the gateway reads no message content and stores nothing');
  if (address.address === '0.0.0.0') {
    console.log('WARNING: bound to all interfaces. Anyone on this network can use it as a relay client.');
  }
  await new Promise((resolve) => process.on('SIGINT', resolve));
  await gateway.close();
}

// One machine, one process, one command: the relay is started here and the gateway that
// serves the page bridges to it over loopback. Two processes stay available for the
// deployment where it matters -- `veil relay` on the box Tor fronts, then
// `veil gateway --relay <onion>:9443 --tor ...` -- because that is what puts a real
// hidden-service address into the invite a peer receives.
export async function startWeb(options = {}) {
  const tor = options.tor ? parseTor(options.tor) : null;
  let relay = null;
  let relayHost;
  let relayPort;

  if (options.relay) {
    ({ relayHost, relayPort } = relayTarget(options.relay));
    guardOnion(relayHost, tor);
  } else {
    relay = createRelayServer();
    relayHost = options.relayHost ?? '127.0.0.1';
    relayPort = options.relayPort ?? DEFAULT_RELAY_PORT;
    const address = await listen(relay.server, relayPort, relayHost).catch((err) => {
      throw portBusy(err, 'the relay', `${relayHost}:${relayPort}`);
    });
    relayHost = '127.0.0.1';
    relayPort = address.port;
  }

  const gateway = createGateway({ relayHost, relayPort, tor });
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? DEFAULT_GATEWAY_PORT;
  let address;
  try {
    address = await listen(gateway.server, port, host);
  } catch (err) {
    // Half a veil web is worse than none: the relay it opened would go on holding a port
    // with no page to serve, and nothing left running to close it.
    if (relay) await relay.close();
    throw portBusy(err, 'the page', `${host}:${port}`);
  }

  return {
    gateway,
    relay,
    url: `http://${address.address === '0.0.0.0' ? '127.0.0.1' : address.address}:${address.port}`,
    port: address.port,
    publicAddress: address.address,
    relayHost,
    relayPort,
    close: async () => {
      await gateway.close();
      if (relay) await relay.close();
    },
  };
}

export async function commandWeb(options = {}) {
  const web = await startWeb(options);
  console.log(`web app on ${web.url}`);
  console.log(
    web.relay
      ? `relay for this chat listening on ${web.relayHost}:${web.relayPort}, in this process`
      : `bridging every page session to the relay at ${web.relayHost}:${web.relayPort}${options.tor ? ' through Tor' : ''}`
  );
  console.log('the relay and the gateway read no message content and store nothing');
  if (web.publicAddress === '0.0.0.0') {
    console.log('WARNING: bound to all interfaces. Anyone on this network can use it as a relay client.');
  }
  console.log('open the URL in a browser, or press ctrl-c to stop');
  await new Promise((resolve) => process.on('SIGINT', resolve));
  await web.close();
}

function parseTor(value) {
  const [proxyHost, proxyPort] = value.split(':');
  return { proxyHost, proxyPort: Number(proxyPort) };
}

