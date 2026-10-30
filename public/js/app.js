// The whole of the page's logic. It renders into the DOM and moves bytes; it holds no
// history, contacts, drafts or keys anywhere a later page load could read them back --
// there is no localStorage, no IndexedDB and no service worker in this file, on purpose.

import { openSession } from './js/session-web.js';
import { HANDLE_LEN, formatInvite, parseInvite } from './js/invite.js';
import { cryptoCapabilities, generateKeypair, randomBytes } from './js/crypto-web.js';
import { fingerprint } from './js/noise-web.js';
import { fromHex } from './js/bytes.js';

const el = (id) => document.getElementById(id);
const screens = ['home', 'invite', 'join', 'chat'];

const state = {
  session: null,
  relay: null,
  nick: 'anonymous',
  staticKeypair: null,
};

function show(name) {
  for (const screen of screens) el(`screen-${screen}`).hidden = screen !== name;
  el('back').hidden = name === 'home';
  el('subtitle').textContent =
    name === 'chat' ? 'end-to-end encrypted, nothing stored' : 'nothing is stored, on either side';
  if (name !== 'chat') el('status-dot').className = 'dot idle';
}

function setStatus(kind) {
  el('status-dot').className = `dot ${kind}`;
}

// Message bodies go in through textContent, never innerHTML: a peer is unverified until
// fingerprints have been compared, so its output is attacker-controlled text.
function bubble(direction, text) {
  const node = document.createElement('div');
  node.className = `bubble ${direction}`;
  const body = document.createElement('span');
  body.textContent = text;
  const meta = document.createElement('time');
  meta.className = 'meta';
  meta.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  node.append(body, meta);
  el('thread').append(node);
  el('thread').scrollTop = el('thread').scrollHeight;
  return node;
}

function note(text) {
  const node = document.createElement('div');
  node.className = 'note';
  node.textContent = text;
  el('thread').append(node);
  el('thread').scrollTop = el('thread').scrollHeight;
}

function banner(text, tone = 'info') {
  const node = el('banner');
  node.hidden = !text;
  node.textContent = text ?? '';
  node.style.background = tone === 'bad' ? '#fbd5d2' : '#fff7d6';
  node.style.color = tone === 'bad' ? '#7d1c16' : '#5c4d0a';
}

async function loadRelay() {
  try {
    const response = await fetch('/info', { cache: 'no-store' });
    const info = await response.json();
    state.relay = info.relay;
    el('relay-name').textContent = info.relay + (info.onion ? ' (onion)' : '');
    el('foot-note').textContent = info.onion
      ? `gateway to ${info.relay} through Tor · no accounts · no history`
      : `gateway to ${info.relay} · no accounts · no history`;
    if (!info.onion) {
      el('foot-note').textContent += ' · WARNING: clearnet relay, your address is visible to it';
    }
  } catch {
    el('foot-note').textContent = 'the gateway did not answer /info';
  }
}

async function gateOnCapabilities() {
  const capabilities = await cryptoCapabilities();
  if (capabilities.ok) return true;
  el('capability').hidden = false;
  el('capability-detail').textContent =
    `Missing: ${capabilities.missing.join(', ')}. ` +
    'Open the page at http://127.0.0.1 (a secure context) in a browser with X25519 support, ' +
    'or use the terminal client instead.';
  el('make-invite').disabled = true;
  el('open-join').disabled = true;
  return false;
}

function requireRelay() {
  if (state.relay) return state.relay;
  throw new Error('the gateway has not told us which relay it bridges to');
}

async function startHosting() {
  const [host, portText] = requireRelay().split(':');
  state.nick = el('nick').value.trim() || 'anonymous';
  const handle = await randomBytes(HANDLE_LEN);
  state.staticKeypair = await generateKeypair();
  show('invite');
  // The invite and join flows share this screen, and only the host has an invite to
  // hand over -- showing a code to copy at someone who is already joining is noise.
  el('invite-send-note').hidden = false;
  el('invite-row').hidden = false;
  el('invite-keep-note').hidden = false;
  el('invite-heading').textContent = 'Waiting for your peer';
  el('invite-code').textContent = formatInvite(host, Number(portText), handle);
  el('invite-waiting').textContent = 'waiting for the invite to be used';
  el('own-fingerprint').textContent = await fingerprint(state.staticKeypair.public);

  try {
    const session = await openSession({
      handle,
      initiator: false,
      staticKeypair: state.staticKeypair,
    });
    enterChat(session);
  } catch (err) {
    el('invite-waiting').textContent = err.message;
    setStatus('gone');
  }
}

async function startJoining() {
  el('join-error').hidden = true;
  let parsed;
  try {
    parsed = parseInvite(el('invite-input').value);
  } catch (err) {
    return failJoin(err.message);
  }
  state.nick = el('nick').value.trim() || 'anonymous';

  const [relayHost, relayPort] = requireRelay().split(':');
  if (parsed.host !== relayHost || String(parsed.port) !== relayPort) {
    return failJoin(
      `this gateway bridges ${relayHost}:${relayPort}, not ${parsed.host}:${parsed.port}. ` +
        'Start the gateway against their relay, or ask them for an invite for yours.'
    );
  }

  let expectedPeer = null;
  const pinned = el('expect-key').value.trim();
  if (pinned) {
    if (!/^[0-9a-fA-F]{64}$/.test(pinned)) {
      return failJoin('a pinned key is 64 hex characters, nothing else');
    }
    expectedPeer = fromHex(pinned.toLowerCase());
  }

  el('join-error').hidden = true;
  show('invite');
  el('invite-send-note').hidden = true;
  el('invite-row').hidden = true;
  el('invite-keep-note').hidden = true;
  el('invite-heading').textContent = 'Connecting';
  // Made here rather than inside openSession so the fingerprint shown while waiting is
  // the one this session actually shakes on -- and so a peer that never arrives leaves
  // a key behind that nothing else ever sees.
  state.staticKeypair = await generateKeypair();
  el('own-fingerprint').textContent = await fingerprint(state.staticKeypair.public);
  el('invite-waiting').textContent = 'waiting for the relay to pair you';
  try {
    const session = await openSession({
      handle: parsed.handle,
      initiator: true,
      expectedPeer,
      staticKeypair: state.staticKeypair,
    });
    enterChat(session);
  } catch (err) {
    if (expectedPeer && /mismatch/.test(err.message)) {
      return failJoin(
        'the peer key did not match the one you pinned. Nothing was sent. If that key came from ' +
          'them, someone is between you -- do not retry and do not tell them anything by typing.'
      );
    }
    failJoin(err.message);
  }
}

function failJoin(message) {
  const node = el('join-error');
  node.textContent = message;
  node.hidden = false;
  show('join');
  setStatus('gone');
}

function enterChat(session) {
  state.session = session;
  show('chat');
  setStatus('live');
  banner(
    'Fingerprints have not been compared. Read them out over a channel this relay does not control ' +
      'before writing anything you would not say in public.'
  );
  el('thread').replaceChildren();
  el('peer-name').textContent = 'peer';
  el('peer-note').textContent = session.peerFingerprint;
  el('peer-fingerprint').textContent = session.peerFingerprint;
  el('my-fingerprint').textContent = session.localFingerprint;
  el('handshake-hash').textContent = session.info.handshakeHash.slice(0, 16);
  el('draft').focus();
  note('keys are made for this session and are not written down');

  session.on('message', (message) => {
    if (message.t === 'nick') {
      el('peer-name').textContent = String(message.body || 'peer');
      return;
    }
    bubble('in', String(message.body ?? ''));
  });
  session.on('close', () => {
    setStatus('gone');
    banner('your peer left. Nothing is kept on either side -- back to start a new chat, or close this tab to forget it.', 'bad');
    el('draft').disabled = true;
  });
  session.on('error', (err) => {
    setStatus('gone');
    banner(err.message, 'bad');
  });

  // Announcing the display name is the first frame of the chat, so it is inside the
  // encryption the peer has just authenticated.
  session.send('nick', state.nick).catch(() => {});
}

function leave() {
  const session = state.session;
  state.session = null;
  el('draft').value = '';
  el('draft').disabled = false;
  el('thread').replaceChildren();
  banner('');
  if (session) session.close().catch(() => {});
  show('home');
}

async function copyInvite() {
  const text = el('invite-code').textContent;
  try {
    await navigator.clipboard.writeText(text);
    el('copy-invite').textContent = 'Copied';
  } catch {
    // Clipboard access is refused in a lot of browser setups; the code is selectable,
    // so the fallback is to say so rather than pretend it worked.
    el('copy-invite').textContent = 'Select it';
  }
  setTimeout(() => {
    el('copy-invite').textContent = 'Copy';
  }, 1600);
}

function wire() {
  el('make-invite').addEventListener('click', () => {
    startHosting().catch((err) => {
      el('invite-waiting').textContent = err.message;
      show('invite');
    });
  });
  el('open-join').addEventListener('click', () => show('join'));
  el('do-join').addEventListener('click', () => {
    startJoining().catch((err) => failJoin(err.message));
  });
  el('copy-invite').addEventListener('click', copyInvite);
  el('back').addEventListener('click', () => {
    if (state.session) leave();
    else show('home');
  });
  el('verify').addEventListener('click', () => el('verify-dialog').showModal());
  el('verify-close').addEventListener('click', () => el('verify-dialog').close());

  el('composer').addEventListener('submit', async (event) => {
    event.preventDefault();
    const session = state.session;
    if (!session) return;
    const text = el('draft').value;
    if (!text.trim()) return;
    el('draft').value = '';
    try {
      await session.send('text', text);
      bubble('out', text);
    } catch (err) {
      el('draft').value = text;
      banner(err.message, 'bad');
    }
  });

  // The page promises nothing survives the tab; a reload must not resurrect a session
  // or a draft from anywhere.
  window.addEventListener('beforeunload', () => {
    if (state.session) state.session.shutdown();
  });
}

wire();
await loadRelay();
await gateOnCapabilities();
show('home');
