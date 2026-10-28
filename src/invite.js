// The rendezvous address format and the JOIN header, free of Node and of the DOM so
// the browser, the CLI and the gateway all parse the same string.

import { alloc, fromHex, toHex } from './bytes.js';

export const PROTOCOL_VERSION = 1;
export const CMD_JOIN = 1;
export const STATUS_OK = 1;
export const STATUS_PEER_GONE = 3;
export const HANDLE_LEN = 16;
export const HANDLE_HEX_LEN = HANDLE_LEN * 2;
export const JOIN_HEADER_LEN = 2 + HANDLE_LEN;

// host:port/handle, where host may be a .onion name or a clearnet address.
export function parseInvite(invite) {
  const match = /^([a-zA-Z0-9.]+):(\d+)\/([0-9a-fA-F]{32})$/.exec(invite.trim());
  if (!match) throw new Error('malformed invite, expected host:port/handle');
  return { host: match[1], port: Number(match[2]), handle: fromHex(match[3].toLowerCase()) };
}

export function formatInvite(host, port, handle) {
  return `${host}:${port}/${toHex(handle)}`;
}

export function joinHeader(handle) {
  if (handle.length !== HANDLE_LEN) throw new Error(`handle must be ${HANDLE_LEN} bytes`);
  const header = alloc(JOIN_HEADER_LEN);
  header[0] = PROTOCOL_VERSION;
  header[1] = CMD_JOIN;
  header.set(handle, 2);
  return header;
}
