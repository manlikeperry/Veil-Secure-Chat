import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { generateKeypair, publicFromPrivate } from './crypto.js';
import { fromHex, toHex } from './bytes.js';
import { fingerprint } from './noise.js';

export function identityDir() {
  return process.env.VEIL_HOME ?? join(homedir(), '.veil');
}

// Only the long-term identity key is persisted, because a stable fingerprint is
// what lets a peer notice a later impersonation. Chat content is never written:
// there is no history file, no database, and no attachment spool.
export async function loadOrCreateIdentity() {
  const path = join(identityDir(), 'identity.json');
  try {
    const stored = JSON.parse(await readFile(path, 'utf8'));
    const privateKey = fromHex(stored.privateKey);
    return {
      private: privateKey,
      // The public half is recomputed from the secret rather than trusted from the
      // file, so an edited or half-written record cannot silently change who a peer
      // thinks they are talking to.
      public: publicFromPrivate(privateKey),
      nick: stored.nick ?? 'anon',
      path,
      created: false,
    };
  } catch {}

  const keypair = await generateKeypair();
  const identity = {
    ...keypair,
    nick: process.env.VEIL_NICK ?? 'anon',
    path,
    created: true,
  };
  await saveIdentity(identity);
  return identity;
}

export async function saveIdentity(identity) {
  await mkdir(identityDir(), { recursive: true });
  await writeFile(
    identity.path,
    JSON.stringify(
      { privateKey: toHex(identity.private), publicKey: toHex(identity.public), nick: identity.nick },
      null,
      2
    )
  );
  // 0600 rather than default 0644: the file holds the private half of the identity
  // key. Windows ignores chmod entirely, so say so instead of pretending it worked.
  const restricted = await chmod(identity.path, 0o600).then(() => true).catch(() => false);
  if (!restricted || process.platform === 'win32') {
    console.warn(
      `note: ${identity.path} holds your private identity key but could not be restricted to your ` +
        'account alone. On Windows, set NTFS permissions on that file or keep VEIL_HOME on an encrypted volume.'
    );
  }
}

export function identityLabel(identity) {
  return fingerprint(identity.public);
}
