import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { Encrypter, Decrypter, generateX25519Identity, identityToRecipient, armor } from 'age-encryption';

const ALGORITHM = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;

/** Encrypt plaintext string → binary buffer [iv(12) | tag(16) | ciphertext] */
export function encrypt(plaintext: string, key: Buffer): Buffer {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]);
}

/** Decrypt binary buffer [iv(12) | tag(16) | ciphertext] → plaintext string */
export function decrypt(data: Buffer, key: Buffer): string {
  const iv = data.subarray(0, IV_LEN);
  const tag = data.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const enc = data.subarray(IV_LEN + TAG_LEN);
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

/** Generate a random 256-bit key */
export function generateKey(): Buffer {
  return randomBytes(32);
}

/** Validate a Buffer is 32 bytes */
export function validateKey(buf: Buffer): void {
  if (buf.length !== 32) throw new Error(`Invalid key length: ${buf.length}, expected 32`);
}

/* ================================================================
   Age (X25519 + ChaCha20-Poly1305) encryption for agent-bound secrets.
   The agent generates an X25519 identity, registers the public key
   with SSS, and only the agent can decrypt what we encrypt for it.

   Plaintext never appears in the API response, on the wire, or in
   any SSS log — only age-ciphertext.
   ================================================================ */

/** Generate a fresh X25519 age identity. */
export async function generateAgentIdentity(): Promise<{
  secretKey: string; // AGE-SECRET-KEY-1...
  publicKey: string;  // age1...
}> {
  const secretKey = await generateX25519Identity();
  const publicKey = await identityToRecipient(secretKey);
  return { secretKey, publicKey };
}

/** Encrypt plaintext for an age recipient (public key like "age1...").
 *  Returns ASCII-armored age ciphertext (PEM-like, safe for HTTP text/plain). */
export async function encryptForRecipient(plaintext: string, recipientPub: string): Promise<string> {
  const enc = new Encrypter();
  enc.addRecipient(recipientPub);
  const cipher = await enc.encrypt(plaintext); // returns Uint8Array
  return armor.encode(cipher);
}

/** Decrypt age-armored ciphertext using an identity (AGE-SECRET-KEY-1...).
 *  Returns the plaintext string. */
export async function decryptWithIdentity(ciphertext: string, secretKey: string): Promise<string> {
  const dec = new Decrypter();
  dec.addIdentity(secretKey);
  const plain = await dec.decrypt(armor.decode(ciphertext), 'text');
  return plain;
}
