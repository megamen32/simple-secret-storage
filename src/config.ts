import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export const SSS_DIR = () => join(homedir(), '.sss');
export const BLOBS_DIR = () => join(SSS_DIR(), 'blobs');
export const KEY_FILE = () => join(SSS_DIR(), 'key');
export const SECRETS_FILE = () => join(SSS_DIR(), 'secrets.json');

export function ensureDirs(): void {
  for (const d of [SSS_DIR(), BLOBS_DIR()]) {
    if (!existsSync(d)) mkdirSync(d, 0o700);
  }
}

export function readKey(): Buffer {
  return readFileSync(KEY_FILE());
}

export function writeKey(key: Buffer): void {
  ensureDirs();
  writeFileSync(KEY_FILE(), key, { mode: 0o600 });
}

/** Validate secret name: only alphanumeric, underscore, dash, dot */
export function sanitizeName(name: string): string {
  const clean = name.replace(/[^a-zA-Z0-9_.-]/g, '_');
  if (!clean) throw new Error('Invalid secret name');
  return clean;
}
