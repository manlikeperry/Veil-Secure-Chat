// The protocol as Node runs it: the shared state machine bound to node:crypto.
// See noise-core.js for the handshake itself and crypto.js for why the interface is
// async. crypto-web.js/noise-web.js are the browser-side twins of this file.

import * as nodeProvider from './crypto.js';
import { makeNoiseApi } from './noise-core.js';

const api = makeNoiseApi(nodeProvider);

export const HandshakeState = api.HandshakeState;
export const CipherState = api.CipherState;
export const FrameReader = api.FrameReader;
export const encryptFrame = api.encryptFrame;
export const fingerprint = api.fingerprint;
export const MAX_TRANSPORT_PAYLOAD = api.MAX_TRANSPORT_PAYLOAD;
export const PROTOCOL_NAME = api.PROTOCOL_NAME;
