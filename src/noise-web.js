// The protocol as a browser runs it: the shared state machine bound to WebCrypto.
// This file has no Node imports, so the gateway serves it to the page verbatim.

import * as webProvider from './crypto-web.js';
import { makeNoiseApi } from './noise-core.js';

const api = makeNoiseApi(webProvider);

export const HandshakeState = api.HandshakeState;
export const CipherState = api.CipherState;
export const FrameReader = api.FrameReader;
export const encryptFrame = api.encryptFrame;
export const fingerprint = api.fingerprint;
export const MAX_TRANSPORT_PAYLOAD = api.MAX_TRANSPORT_PAYLOAD;
export const PROTOCOL_NAME = api.PROTOCOL_NAME;
