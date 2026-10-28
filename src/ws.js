// A minimal RFC 6455 WebSocket server, written against nothing but node:crypto and
// the socket it is handed. The browser cannot open a TCP connection to the relay, so
// this is the one bridge between a page and the byte pipe -- and a bridge is all it
// ever becomes: it frames bytes, it never reads them.
//
// Scope deliberately left out: no extensions (permessage-deflate is declined, which
// also avoids the CRIME/BREACH class of oracle), no text frames in either direction
// (every message is binary so a UTF-8 validation failure cannot be used to kill a
// session), no client role, and no fragmentation of outbound messages because a chat
// frame is never near the 64 KiB transport limit.

import { createHash, randomBytes } from 'node:crypto';

const WEBSOCKET_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const OP_CONTINUATION = 0x0;
const OP_CLOSE = 0x8;
const OP_PING = 0x9;
const OP_PONG = 0xa;

// The two statuses this server ever sends. 1011 is "unexpected condition", which is
// what a refused frame is; 1001 is "going away", which is what a relay that dropped
// out from under a page is.
const CLOSE_PROTOCOL_ERROR = 1011;
const CLOSE_GOING_AWAY = 1001;

// A reassembled message larger than this is a peer trying to exhaust memory. The
// protocol itself caps a transport frame at 65535 bytes plus overhead, so this is
// already orders of magnitude above anything a real session produces.
export const MAX_MESSAGE_BYTES = 262144;
const MAX_CONTROL_BYTES = 125;

export function acceptFor(clientKey) {
  return createHash('sha1').update(clientKey + WEBSOCKET_GUID).digest('base64');
}

// The key is 16 random bytes in base64, which is 22 characters plus the two `=` that
// base64 pads a length-164 remainder to -- RFC 6455's own example,
// dGhlIHNhbXBsZSBub25jZQ==, has exactly that shape. A key of any other length would
// still hash to something, so this must fail the handshake rather than open a
// connection that breaks on the first frame.
export function isClientKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{22}==$/.test(value)) return false;
  return Buffer.from(value, 'base64').length === 16;
}

function maskInPlace(payload, key) {
  for (let i = 0; i < payload.length; i += 1) payload[i] ^= key[i & 3];
}

// A client->server frame must be masked; a server->client frame must not be. Anything
// else is a protocol violation and gets the connection dropped rather than decoded --
// an unmasked client frame is the classic signature of something that is not a
// browser talking to the port.
export function encodeFrame(opcode, payload, { fin = true, mask = false } = {}) {
  const len = payload.length;
  let headerLength = 2;
  if (len > 125 && len <= 65535) headerLength = 4;
  else if (len > 65535) headerLength = 10;

  const frame = Buffer.alloc(headerLength + (mask ? 4 : 0) + len);
  frame[0] = (fin ? 0x80 : 0x00) | opcode;
  if (len <= 125) frame[1] = len;
  else if (len <= 65535) {
    frame[1] = 126;
    frame.writeUInt16BE(len, 2);
  } else {
    frame[1] = 127;
    frame.writeBigUInt64BE(BigInt(len), 2);
  }
  frame[1] |= mask ? 0x80 : 0;

  const body = frame.subarray(headerLength);
  if (mask) {
    const key = randomBytes(4);
    key.copy(body, 0);
    payload.copy(body, 4);
    maskInPlace(body.subarray(4), key);
  } else {
    body.set(payload);
  }
  return frame;
}

// Incremental decoder: bytes arrive in whatever pieces the network felt like, so the
// parser holds a buffer and a stage rather than assuming one chunk is one frame.
//
// `expectMasked` is the direction rule. A server must require masking from clients
// (it is what stops non-browser traffic from speaking the protocol and what defeats
// proxy-cache key smearing); a client must accept unmasked frames from the server,
// because masking is only mandated in the client->server direction.
export class FrameParser {
  constructor({ onMessage, onPing, onPong, onClose, expectMasked = true }) {
    this.buffer = Buffer.alloc(0);
    this.onMessage = onMessage;
    this.onPing = onPing;
    this.onPong = onPong ?? (() => {});
    this.onClose = onClose;
    this.expectMasked = expectMasked;
    // A fragmented message accumulates here. The size cap covers the whole message,
    // not each fragment, or fragmentation would be a way around it.
    this.partial = [];
    this.partialBytes = 0;
  }

  push(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    for (;;) {
      const consumed = this._parseOne();
      if (consumed === 0) return;
      this.buffer = this.buffer.subarray(consumed);
    }
  }

  _parseOne() {
    const b = this.buffer;
    if (b.length < 2) return 0;

    const fin = (b[0] & 0x80) !== 0;
    const opcode = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let length = b[1] & 0x7f;
    let offset = 2;

    if (length === 126) {
      if (b.length < offset + 2) return 0;
      length = b.readUInt16BE(offset);
      offset += 2;
    } else if (length === 127) {
      if (b.length < offset + 8) return 0;
      const wide = b.readBigUInt64BE(offset);
      if (wide > BigInt(MAX_MESSAGE_BYTES)) throw new Error('websocket frame is absurdly large');
      length = Number(wide);
      offset += 8;
    }

    const isControl = opcode >= 0x8;
    if (isControl && (length > MAX_CONTROL_BYTES || !fin)) {
      throw new Error('control frame is too long or fragmented');
    }
    if (opcode === OP_CONTINUATION && !fin && this.partial.length === 0 && length === 0) {
      throw new Error('empty continuation sequence');
    }

    if (this.expectMasked && !masked) throw new Error('client frame must be masked');
    const maskBytes = masked ? 4 : 0;
    if (b.length < offset + maskBytes + length) return 0;

    const payload = Buffer.from(b.subarray(offset + maskBytes, offset + maskBytes + length));
    if (masked) maskInPlace(payload, b.subarray(offset, offset + 4));
    const consumed = offset + maskBytes + length;

    if (isControl) {
      if (opcode === OP_PING) this.onPing(payload);
      else if (opcode === OP_PONG) this.onPong(payload);
      else if (opcode === OP_CLOSE) this.onClose(payload);
      return consumed;
    }

    this.partialBytes += payload.length;
    if (this.partialBytes > MAX_MESSAGE_BYTES) throw new Error('websocket message exceeds the size cap');
    if (opcode !== OP_CONTINUATION && this.partial.length > 0) {
      throw new Error('a new message started before the last one finished');
    }
    if (opcode !== OP_CONTINUATION) this.partial = [];
    this.partial.push(payload);

    if (fin) {
      const message = Buffer.concat(this.partial, this.partialBytes);
      this.partial = [];
      this.partialBytes = 0;
      this.onMessage(message, opcode);
    }
    return consumed;
  }
}

// One upgraded connection. The host sets `onMessage` and `onClosed`; `send` writes a
// single unmasked binary frame and ordering is guaranteed by waiting for drain rather
// than letting two writes interleave.
export class WebSocketConnection {
  constructor(socket) {
    this.socket = socket;
    this.closed = false;
    this.pending = Promise.resolve();
    this.onMessage = null;
    this.onClosed = null;
    this.parser = new FrameParser({
      onMessage: (message) => this.onMessage?.(message),
      onPing: (payload) => this._write(encodeFrame(OP_PONG, payload)),
      onClose: () => this.close(),
    });
    socket.on('data', (chunk) => {
      try {
        this.parser.push(chunk);
      } catch (err) {
        // The message is one of this file's own strings, so quoting it tells the page
        // which rule it broke without echoing anything the peer wrote.
        this.fail(err.message, CLOSE_PROTOCOL_ERROR);
      }
    });
    socket.on('close', () => this._dead());
    socket.on('error', () => this._dead());
  }

  send(bytes) {
    const payload = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    // Chained so a slow reader cannot make two frames race each other onto the wire.
    this.pending = this.pending.then(() => this._write(encodeFrame(0x2, payload))).catch(() => {});
    return this.pending;
  }

  async _write(frame) {
    if (this.closed || this.socket.destroyed) return;
    if (this.socket.write(frame)) return;
    await new Promise((resolve) => {
      const done = () => {
        this.socket.removeListener('drain', done);
        this.socket.removeListener('close', done);
        this.socket.removeListener('error', done);
        resolve();
      };
      this.socket.once('drain', done);
      this.socket.once('close', done);
      this.socket.once('error', done);
    });
  }

  close() {
    // Status 1005 -- "no status code was present" -- is what the peer reports back,
    // which is the honest answer for a session that simply ended.
    this._bye(Buffer.alloc(0));
  }

  fail(reason = 'the relay could not be reached', code = CLOSE_GOING_AWAY) {
    let text = Buffer.from(String(reason), 'utf8');
    // A close frame is a control frame, so it may not exceed 125 bytes: 2 for the
    // status and the rest for the reason.
    if (text.length > MAX_CONTROL_BYTES - 2) text = text.subarray(0, MAX_CONTROL_BYTES - 2);
    const body = Buffer.alloc(2 + text.length);
    body.writeUInt16BE(code, 0);
    body.set(text, 2);
    this._bye(body);
  }

  _bye(body) {
    if (this.closed) return;
    this.closed = true;
    // Written straight to the socket instead of through _write, whose guard is there
    // to drop ordinary sends on a dead connection -- and would otherwise drop this one
    // too, leaving the page to guess that the relay was unreachable from a socket that
    // silently vanished. end() flushes the frame before the FIN, so the peer reads it.
    if (!this.socket.destroyed) {
      try {
        this.socket.write(encodeFrame(OP_CLOSE, body));
      } catch {}
    }
    this.socket.end();
    this.onClosed?.();
  }

  _dead() {
    if (this.closed) return;
    this.closed = true;
    this.onClosed?.();
  }
}

// Completes the opening handshake on an `upgrade` event and hands back the connection.
export function upgrade(req, socket, head) {
  const key = req.headers['sec-websocket-key'];
  if (!isClientKey(key)) {
    // end(data) rather than write(data) + destroy(): destroy() discards whatever is
    // still in the socket's output buffer, so the refusal would never reach the caller.
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    return null;
  }
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
      `Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acceptFor(key)}\r\n\r\n`
  );
  const ws = new WebSocketConnection(socket);
  // Any bytes that arrived in the same packet as the GET belong to the first frame.
  if (head && head.length) {
    try {
      ws.parser.push(head);
    } catch {
      ws.fail();
    }
  }
  return ws;
}
