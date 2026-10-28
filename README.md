# veil

Chat with no account, no message storage, and — when run over Tor — no server that
can see your IP. Zero runtime dependencies: Node built-ins only.

It is a protocol + relay + terminal client + browser client. Not a mobile app yet;
`src/crypto.js` is the single file a React Native build replaces.

## Quickstart (three terminals)

Terminal 1 — the relay. It stores nothing and logs nothing.

```
node src/veil.js relay --port 9443
```

Terminal 2 — invite. Prints an invite string and waits.

```
node src/veil.js invite --relay 127.0.0.1:9443
```

Terminal 3 — join, using the invite string exactly as printed.

```
node src/veil.js join 127.0.0.1:9443/<handle>
```

Type to send. `/quit` leaves. Nothing is written to disk except your identity key at
`~/.veil/identity.json` (set `VEIL_HOME` to relocate).

`veil identity` shows your fingerprint. Both peers see each other's fingerprint after
the handshake — compare it over a channel the relay does not control, or the relay
operator can impersonate your peer. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Running over Tor (this is what hides the IP)

The `127.0.0.1` walkthrough above is for development: a cleartext relay does see
connecting IPs. To get the actual property, run the relay behind an onion service
(`tor/relay-torrc`) and pass `--tor`:

```
node src/veil.js invite --relay abc123...onion:9443 --tor 127.0.0.1:9050
node src/veil.js join   abc123...onion:9443/<handle> --tor 127.0.0.1:9050
```

`--tor` points at a SOCKS5 listener: `9050` for a `tor` daemon, `9150` for Tor
Browser. `.onion` names are resolved *by Tor*, never locally, so neither the DNS
query nor the connection ever carries your IP. Dialing `.onion` without `--tor` is a
hard error rather than a fallback.

## Web chat in a browser

A page cannot open a TCP socket, so a gateway sits between the browser and the relay: it
serves the app and pipes each page's WebSocket bytes to one relay connection. It joins
bytes and never reads them — no JOIN header parsing, no frame parsing — so running it
costs nothing in trust.

**One command is the whole setup.** `veil web` starts the relay and the gateway in the
same process, which is all a chat between two clients on this machine needs:

```
node src/veil.js web
```

```
web app on http://127.0.0.1:9444
relay for this chat listening on 127.0.0.1:9443, in this process
the relay and the gateway read no message content and store nothing
open the URL in a browser, or press ctrl-c to stop
```

Two processes, when the relay is not this machine's to start — a relay already running,
or the onion deployment below:

```
node src/veil.js relay   --port 9443
node src/veil.js gateway --port 9444 --relay 127.0.0.1:9443
```

Open **http://127.0.0.1:9444** — not a LAN address, because a browser only hands out
`crypto.subtle` (X25519, AES-GCM) in a secure context, and plain http qualifies on
loopback alone. Three screens: make an invite, join with one, chat. Each tab generates
its session key when it needs one and keeps it in memory; there is no localStorage, no
IndexedDB, no service worker and no cookie anywhere in `public/`, so closing the tab
really is the end of the conversation. A terminal peer can join a browser invite and
vice versa — the two use the same handshake, verified against each other below. An
invite printed by the page names the *relay*, so `veil join` dials it directly and never
passes through the gateway.

For the IP property, add `--tor` so the gateway dials the onion relay through Tor. With
an onion relay the two-process form is the honest one, because the relay belongs on the
machine Tor fronts and the invite has to carry its hidden-service address:

```
node src/veil.js gateway --port 9444 --relay abc123...onion:9443 --tor 127.0.0.1:9050
```

The page then travels nowhere: browser → gateway is the same machine, and gateway →
relay is inside Tor. Loading the app from `127.0.0.1` does not expose your address to
the relay. It does expose it to whoever runs the gateway, which is why the gateway
binds loopback by default and warns if you make it listen on every interface.

## Tests

```
node test/run.js
```

54 checks in seven suites. Handshake: the official `Noise_XX` known-answer vector
replayed byte for byte, transcript hashes equal on both sides, both directions
encrypted, tampered and replayed frames rejected, key rotation at 65536 messages.
Crypto: the Node and WebCrypto providers produce identical primitives, and a Node peer
and a WebCrypto peer complete a handshake and read each other in both role orders — so
the browser and the terminal are the same protocol, not two lookalikes. Relay: lane
lifecycle, a second JOIN on a paired handle cannot hijack it, early bytes buffered
rather than reparsed as a header, plaintext absent from forwarded bytes. WebSocket:
RFC 6455 accept vector, masking enforced, fragmentation, control-frame rules, size caps.
Gateway: a handshake crossing the bridge untouched, refusal of cross-origin upgrades and
of every path outside the file allowlist, a dead relay closing the page instead of
hanging it, `veil web` bringing up a relay that the page can talk through, a busy port
named instead of dumped. CLI: chat rendering with a live peer (prompt redraw, row
clearing, no escape junk on pipes or dumb terminals).

## Layout

| Path | Role |
|---|---|
| `src/crypto.js` | X25519, HKDF, AES-256-GCM from Node's OpenSSL. One provider behind `src/noise.js`. |
| `src/crypto-web.js` | The same primitives from `crypto.subtle`, for the browser. |
| `src/noise-core.js` | `Noise_XX_25519_AESGCM_SHA256` handshake, transport ratchet, framing — provider-agnostic. |
| `src/noise.js` / `src/noise-web.js` | The core bound to each provider. |
| `src/session-core.js` | The chat state machine: join, handshake, encrypted JSON frames. Shared by both clients. |
| `src/client.js` / `src/session-web.js` | That machine over a TCP socket / over a WebSocket. |
| `src/ws.js` | RFC 6455 server: accept handshake, frame codec, masked-frame enforcement. |
| `src/gateway.js` | Serves the page, bridges one WebSocket to one relay connection, and starts both as `veil web`. |
| `src/relay.js` | RAM-only rendezvous pipe; front it with a Tor onion service |
| `src/invite.js` | The wire protocol's shared constants and the invite text format. |
| `src/socks5.js` | SOCKS5 client that delegates `.onion` resolution to Tor |
| `src/cli.js` | Command dispatch and the terminal chat renderer |
| `src/veil.js` | Entry point — `node src/veil.js <command>` |
| `public/` | The web client: one HTML file, one stylesheet, one module. |
| `tor/relay-torrc` | Onion service deployment |
| `docs/THREAT_MODEL.md` | What is and is not protected, and what still needs review |

## Not done yet

Padding and cover traffic (message size and timing still leak, in the browser exactly
as much as in the terminal), a rate-limited relay, group chats, offline delivery, and
the React Native shell with a real Tor library — `ImageKit`/`TorD` on Android,
`TorKit` on iOS — plus native networking, because JS `WebSocket` cannot route through a
SOCKS proxy or resolve `.onion` on its own. The gateway speaks plain HTTP and relies on
loopback being a secure context; serving the page to a remote machine would need TLS,
which means a certificate, which means a name, which is the kind of thing this app is
trying not to have.

## Runtime note

Requires Node 20+. On this machine there is no `npm` and no standalone `node` on PATH,
so `npm start` fails and `node src/...` fails: Node only exists as Qoder's Electron
binary, run with `ELECTRON_RUN_AS_NODE=1`. Every command above works once that prefix
replaces `node`. In Git Bash, the whole web setup is one line:

```
cd /c/Users/hljah/Documents/Qoder/2026-10-15/4135f98d
ELECTRON_RUN_AS_NODE=1 "C:/Users/hljah/AppData/Local/Programs/Qoder/Qoder.exe" src/veil.js web
# then open http://127.0.0.1:9444 in a browser
```

The `scripts` in `package.json` (`npm start`, `npm run web`, `npm run relay`,
`npm run gateway`) are the same commands and need a real Node install. Until then,
**double-click `start-web.cmd`** in the project folder: it finds Qoder's Node runtime,
sets `ELECTRON_RUN_AS_NODE`, and runs `veil web` on port 9444 using paths taken from its
own location, so nothing has to be on `PATH`.

Two failure messages worth knowing, because both mean "something is already running":

- `the relay cannot start: 127.0.0.1:9443 is already taken` — a `veil relay` or `veil web`
  is still up. Stop it, or bridge the one you have with
  `veil web --relay 127.0.0.1:9443 --port 9444`.
- **the gateway refused or closed the connection** in the page — its websocket to
  `ws://<the same host:port>/relay` never opened: no gateway on the port the page was
  loaded from, or the page was opened as a `file://` and has no gateway at all.
