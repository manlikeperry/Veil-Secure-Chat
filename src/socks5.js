// Minimal SOCKS5 client, used to hand .onion resolution to Tor instead of doing
// it locally. That delegation is the whole point: a local DNS lookup for a hidden
// service would leak the query, and a local connect would expose the client IP.
//
// This is the same seam the mobile build needs -- Android's OkHttp and iOS's
// URLSession are configured with Tor's SOCKS listener and get the identical
// behaviour, so the wire logic above it does not fork per platform.

import net from 'node:net';

const SOCKS5_VERSION = 0x05;
const AUTH_NONE = 0x00;
const CMD_CONNECT = 0x01;
const ATYP_DOMAIN = 0x03;
const REP_SUCCEEDED = 0x00;

const REPLY_MIN = 10;

export function connectThroughSocks5({ proxyHost = '127.0.0.1', proxyPort = 9050, targetHost, targetPort, timeoutMs = 60000 }) {
  return new Promise((resolve, reject) => {
    if (!/^[a-zA-Z0-9.-]+$/.test(targetHost)) {
      reject(new Error('SOCKS5 domain target contains unsupported characters'));
      return;
    }

    const socket = net.connect(proxyPort, proxyHost);
    let stage = 0; // 0 = awaiting method selection, 1 = awaiting connect reply
    let buffer = Buffer.alloc(0);
    let settled = false;

    const fail = (error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };

    socket.setTimeout(timeoutMs, () => fail(new Error('SOCKS5 proxy timed out -- is Tor running?')));
    socket.on('error', (err) => fail(err));

    socket.write(Buffer.from([SOCKS5_VERSION, 1, AUTH_NONE]));

    socket.on('data', (chunk) => {
      if (settled) return;
      buffer = Buffer.concat([buffer, chunk]);

      if (stage === 0) {
        if (buffer.length < 2) return;
        if (buffer[0] !== SOCKS5_VERSION) return fail(new Error('proxy is not SOCKS5'));
        if (buffer[1] !== AUTH_NONE) return fail(new Error('proxy requires authentication we do not support'));
        buffer = buffer.subarray(2);
        stage = 1;

        const host = Buffer.from(targetHost, 'ascii');
        const request = Buffer.alloc(7 + host.length + 2);
        request[0] = SOCKS5_VERSION;
        request[1] = CMD_CONNECT;
        request[2] = 0x00;
        request[3] = ATYP_DOMAIN;
        request[4] = host.length;
        host.copy(request, 5);
        request.writeUInt16BE(targetPort, 5 + host.length);
        socket.write(request);
        return;
      }

      if (buffer.length < REPLY_MIN) return;
      if (buffer[1] !== REP_SUCCEEDED) {
        const reasons = {
          1: 'general SOCKS server failure',
          2: 'connection not allowed by ruleset',
          3: 'network unreachable',
          4: 'host unreachable',
          6: 'requested address family not supported',
          8: 'address type not supported',
        };
        return fail(new Error(`Tor refused the connection: ${reasons[buffer[1]] ?? 'code ' + buffer[1]}`));
      }

      settled = true;
      socket.setTimeout(0);
      // Bytes that rode in with the SOCKS reply belong to the tunnel; unshift puts
      // them back at the head of the stream for whoever reads next.
      const ahead = buffer.subarray(REPLY_MIN);
      if (ahead.length > 0) socket.unshift(ahead);
      resolve(socket);
    });
  });
}

export function isOnion(host) {
  return /\.onion$/i.test(host);
}
