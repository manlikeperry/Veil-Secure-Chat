#!/usr/bin/env node
// veil -- terminal client.
//
// Two commands do the whole job: `invite` publishes a handle and waits, `join`
// dials an invite. Both perform Noise_XX over the relay pipe, so the only thing the
// relay ever sees is an 18-byte JOIN header followed by opaque bytes.

import readline from 'node:readline';
import { toHex, fromHex } from './bytes.js';
import { createRelayServer, makeHandle, formatInvite, parseInvite, listen, DEFAULT_PORT } from './relay.js';
import { Session } from './client.js';
import { loadOrCreateIdentity, identityLabel, saveIdentity, identityDir } from './identity.js';
import { isOnion } from './socks5.js';

const USAGE = `veil -- metadata-minimal chat over a Tor onion relay

  veil web     [--port N] [--relay-port N] [--relay H:P] [--tor ip:p]
                                         one command: relay plus the web chat UI
  veil relay   [--port N] [--host H]     run the stateless relay (front it with Tor)
  veil gateway [--port N] --relay H:P [--tor ip:p]
                                         serve the web chat UI and bridge it to the relay
  veil identity [--nick NAME]            show or set the local fingerprint and key
  veil invite  --relay H:P [--tor ip:p]  publish a handle and wait for a peer
  veil join    <invite> [--tor ip:p] [--expect-key <64-hex public key>]
  veil help

  --tor is required for any .onion relay address; without it the connection aborts
  rather than leaking a DNS lookup or the local IP.`;

function parseArgs(argv) {
  const options = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--port') options.port = Number(argv[++i]);
    else if (token === '--host') options.host = argv[++i];
    else if (token === '--relay') options.relay = argv[++i];
    else if (token === '--relay-port') options.relayPort = Number(argv[++i]);
    else if (token === '--tor') options.tor = argv[++i];
    else if (token === '--nick') options.nick = argv[++i];
    else if (token === '--expect-key') options.expectKey = argv[++i];
    else options._.push(token);
  }
  return options;
}

// --tor accepts ip:port and defaults to the Tor Browser SOCKS listener.
function torOptions(value) {
  if (!value) return null;
  const [host, port] = value.split(':');
  return { proxyHost: host, proxyPort: Number(port) };
}

function splitRelay(value) {
  const match = /^([a-zA-Z0-9.-]+):(\d+)$/.exec(value ?? '');
  if (!match) throw new Error('--relay must look like host:port');
  return { host: match[1], port: Number(match[2]) };
}

function guardDirectOnion(host, tor) {
  if (isOnion(host) && !tor) {
    throw new Error(
      `${host} is a hidden service. Refusing to resolve or dial it directly: that would leak both the lookup and your IP. Pass --tor 127.0.0.1:9150 (Tor Browser) or 127.0.0.1:9050 (tor daemon).`
    );
  }
}

async function commandRelay(options) {
  const relay = createRelayServer();
  const address = await listen(relay.server, options.port ?? DEFAULT_PORT, options.host ?? '127.0.0.1');
  console.log(`relay listening on ${address.address}:${address.port}`);
  console.log('storing nothing; front this with a Tor onion service and clients cannot see your IP');
  console.log('press ctrl-c to stop');
  await new Promise((resolve) => process.on('SIGINT', resolve));
  await relay.close();
}

async function commandIdentity(options) {
  const identity = await loadOrCreateIdentity();
  if (options.nick) {
    identity.nick = options.nick;
    await saveIdentity(identity);
  }
  if (identity.created) console.log(`created a new identity at ${identityDir()}`);
  console.log(`nick         ${identity.nick}`);
  console.log(`fingerprint  ${await identityLabel(identity)}`);
  console.log(`public key   ${toHex(identity.public)}`);
  console.log('keep the private half on this machine; it is what a peer pins against');
}

async function commandInvite(options) {
  const relay = splitRelay(options.relay);
  const tor = torOptions(options.tor);
  guardDirectOnion(relay.host, tor);

  const identity = await loadOrCreateIdentity();
  if (options.nick) {
    identity.nick = options.nick;
    await saveIdentity(identity);
  }

  const handle = makeHandle();
  // connect() resolves only once the peer has joined, so the invite must be printed
  // before awaiting it -- otherwise it arrives after it is useful.
  const pending = Session.connect({
    ...relay,
    handle,
    staticKeypair: identity,
    initiator: false,
    tor,
  });
  console.log(`your fingerprint ${await identityLabel(identity)} -- give this to your peer out of band`);
  console.log(`invite: ${formatInvite(relay.host, relay.port, handle)}`);
  console.log('waiting for the peer to join...');

  const session = await pending.catch((err) => {
    throw new Error(`rendezvous failed: ${err.message}`);
  });
  reportPeer(session, null);
  attachChat(session);
}

async function commandJoin(options) {
  const invite = options._[0];
  if (!invite) throw new Error('usage: veil join <invite> [--tor ip:p] [--expect-key <public key hex>]');
  const parsed = parseInvite(invite);
  const tor = torOptions(options.tor);
  guardDirectOnion(parsed.host, tor);

  const identity = await loadOrCreateIdentity();
  const expectedPeer = options.expectKey ? parseExpectedKey(options.expectKey) : null;

  const session = await Session.connect({
    host: parsed.host,
    port: parsed.port,
    handle: parsed.handle,
    staticKeypair: identity,
    initiator: true,
    expectedPeer,
    tor,
  });

  reportPeer(session, expectedPeer);
  attachChat(session);
}

// Both halves of a conversation must see the other's fingerprint, or the one side
// that never looks has no way to notice a later impersonation.
function reportPeer(session, expectedPeer) {
  console.log(`peer fingerprint ${session.peerFingerprint}`);
  if (expectedPeer) {
    console.log('peer key pinned before the handshake -- any mismatch would have aborted');
    return;
  }
  console.log(
    'WARNING: not pinned. Read this fingerprint aloud or compare it over a channel the relay' +
      ' does not control before writing anything sensitive. Without that check, an attacker who' +
      ' controls the relay can impersonate your peer.'
  );
  console.log('type to send, /nick NAME to show a name, /quit to leave');
}

// Pinning needs the peer's full 32-byte public key. The 8-byte fingerprint shown in
// chat is for comparing out of band, not for pre-handshake pinning -- the key is
// encrypted during XX and cannot be checked before it is received.
function parseExpectedKey(value) {
  if (/^[0-9a-f]{64}$/i.test(value)) return fromHex(value.toLowerCase());
  throw new Error('--expect-key wants a 64-hex-character public key, not a short fingerprint');
}

export function attachChat(session, io = {}) {
  const output = io.output ?? process.stdout;
  const rl = readline.createInterface({
    input: io.input ?? process.stdin,
    output,
    prompt: '> ',
  });

  // Mirrors readline's own internal test: it only redraws when .terminal is set and
  // TERM is not "dumb". Writing escape codes outside that condition puts literal junk
  // into a pipe; skipping the clear lets the notice land on the same row as the
  // half-typed line.
  const redraws = () => rl.terminal && process.env.TERM !== 'dumb';

  // A message can arrive while a line is half-typed. pause() stops stdin from
  // emitting, the row is cleared, the notice is written, then the prompt and the
  // partial input are redrawn. Preserving the cursor is what stops the next keystroke
  // landing at column 0, i.e. inside the middle of what you had already typed.
  const print = (line) => {
    rl.pause();
    if (redraws()) output.write('\r\x1b[K');
    output.write(`${line}\n`);
    rl.prompt(redraws());
    rl.resume();
  };

  rl.prompt();

  session.on('message', (message) => {
    print(`peer: ${message.body ?? ''}`);
  });
  session.on('close', () => {
    print('the peer disconnected; nothing was written to disk');
    rl.close();
  });
  session.on('error', (err) => {
    print(`session aborted: ${err.message}`);
    rl.close();
  });

  rl.on('line', (line) => {
    const text = line.trim();
    if (!text) return;
    if (text === '/quit') {
      session.close();
      return;
    }
    // The display name is only ever sent inside an encrypted frame, and it is
    // attacker-controlled text on the other side, so the UI must treat it as data.
    const nick = /^\/nick(?:\s+(.*))?$/.exec(text);
    if (nick) {
      Promise.resolve(session.send('nick', (nick[1] ?? '').trim() || 'anon')).catch((err) => print(err.message));
      return;
    }
    // Frames are encrypted through WebCrypto-shaped async primitives, so a send can
    // fail after the line has already been accepted. Report it rather than drop it.
    Promise.resolve(session.send('text', text)).catch((err) => print(err.message));
  });
}

// Exported rather than run on import: src/veil.js is the entry point, so a test can
// import attachChat without executing a command as a side effect.
export async function main(argv = process.argv.slice(2)) {
  const command = argv.shift() ?? 'help';
  const options = parseArgs(argv);

  try {
    if (command === 'relay') await commandRelay(options);
    else if (command === 'web') await (await import('./gateway.js')).commandWeb(options);
    else if (command === 'gateway') await (await import('./gateway.js')).commandGateway(options);
    else if (command === 'identity') await commandIdentity(options);
    else if (command === 'invite') await commandInvite(options);
    else if (command === 'join') await commandJoin(options);
    else console.log(USAGE);
  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
  }
}
