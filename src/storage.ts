import { readFileSync, writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { encrypt, decrypt, generateKey, validateKey, encryptForRecipient } from './crypto.js';
import { sanitizeName, SSS_DIR, BLOBS_DIR, KEY_FILE, SECRETS_FILE, ensureDirs } from './config.js';

export interface AgentKey {
  agent_id: string;
  publicKey: string;     // age1...
  registered: string;    // ISO
  lastSeen: string;      // ISO
  label?: string;
}

const AGENTS_FILE = () => join(SSS_DIR(), 'agents.json');

export interface SecretMeta {
  description?: string;
  url?: string;
  account?: string;
  sha256: string;
  created: string;
  /** When true, the secret has no value yet — the user must open
   *  /i/<inputToken> and submit it. `inputToken` carries the token. */
  pending?: boolean;
  /** 256-bit one-time token that lets an anonymous user fill in the
   *  value via the /i/<inputToken> form. Cleared after first submit. */
  inputToken?: string;
  /** ISO timestamp of when the inputToken was issued. */
  inputTokenIssuedAt?: string;
}

function readJson<T = Record<string, any>>(path: string): T {
  if (!existsSync(path)) return {} as T;
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

function writeJson(path: string, data: Record<string, any>): void {
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
}

export class Storage {
  constructor() {
    ensureDirs();
    if (!existsSync(KEY_FILE())) {
      writeFileSync(KEY_FILE(), generateKey(), { mode: 0o600 });
    }
  }

  getKey(): Buffer {
    const k = readFileSync(KEY_FILE());
    validateKey(k);
    return k;
  }

  /* ---- secrets ---- */

  getSecret(name: string): { blob: Buffer; meta: SecretMeta } | null {
    const clean = sanitizeName(name);
    const secrets = readJson<Record<string, SecretMeta>>(SECRETS_FILE());
    const meta = secrets[clean];
    if (!meta) return null;
    const blobPath = join(BLOBS_DIR(), `${clean}.enc`);
    if (!existsSync(blobPath)) return null;
    return { blob: readFileSync(blobPath), meta };
  }

  getSecretMeta(name: string): SecretMeta | null {
    const clean = sanitizeName(name);
    return readJson<Record<string, SecretMeta>>(SECRETS_FILE())[clean] ?? null;
  }

  getSecretBlob(name: string): Buffer | null {
    const clean = sanitizeName(name);
    const p = join(BLOBS_DIR(), `${clean}.enc`);
    return existsSync(p) ? readFileSync(p) : null;
  }

  saveSecret(
    name: string,
    plaintext: string,
    extra?: { description?: string; url?: string; account?: string },
  ): void {
    const clean = sanitizeName(name);
    const key = this.getKey();
    writeFileSync(join(BLOBS_DIR(), `${clean}.enc`), encrypt(plaintext, key), { mode: 0o600 });

    const secrets = readJson<Record<string, SecretMeta>>(SECRETS_FILE());
    const sha256 = createHash('sha256').update(plaintext).digest('hex');
    secrets[clean] = {
      description: extra?.description ?? secrets[clean]?.description,
      url: extra?.url ?? secrets[clean]?.url,
      account: extra?.account ?? secrets[clean]?.account,
      sha256,
      created: secrets[clean]?.created ?? new Date().toISOString(),
    };
    writeJson(SECRETS_FILE(), secrets);
  }

  updateMeta(
    name: string,
    patch: { description?: string; url?: string; account?: string },
  ): boolean {
    const clean = sanitizeName(name);
    const secrets = readJson<Record<string, SecretMeta>>(SECRETS_FILE());
    if (!(clean in secrets)) return false;
    Object.assign(secrets[clean], patch);
    writeJson(SECRETS_FILE(), secrets);
    return true;
  }

  deleteSecret(name: string): boolean {
    const clean = sanitizeName(name);
    const secrets = readJson<Record<string, SecretMeta>>(SECRETS_FILE());
    if (!(clean in secrets)) return false;
    delete secrets[clean];
    writeJson(SECRETS_FILE(), secrets);
    const blobPath = join(BLOBS_DIR(), `${clean}.enc`);
    if (existsSync(blobPath)) unlinkSync(blobPath);
    return true;
  }

  listSecrets(): Array<{ name: string; meta: SecretMeta }> {
    const secrets = readJson<Record<string, SecretMeta>>(SECRETS_FILE());
    return Object.entries(secrets).map(([name, meta]) => ({ name, meta }));
  }

  /** Decrypt blob and return plaintext (used for one-time decrypt URLs) */
  decryptSecret(name: string): string | null {
    const entry = this.getSecret(name);
    if (!entry) return null;
    return decrypt(entry.blob, this.getKey());
  }

  /* ---- pending (anonymous user input) ---- */

  /** Look up a secret name by its anonymous input token. Returns the
   *  sanitized secret name if the token is valid and the secret is
   *  still pending. */
  resolveInputToken(token: string): { name: string; meta: SecretMeta } | null {
    if (!token) return null;
    const secrets = readJson<Record<string, SecretMeta>>(SECRETS_FILE());
    for (const [name, meta] of Object.entries(secrets)) {
      if (meta.pending && meta.inputToken === token) return { name, meta };
    }
    return null;
  }

  /** Fill in the value for a pending secret. Clears pending + inputToken,
   *  writes the encrypted blob, computes sha256. Returns the sanitized
   *  name on success or null if the token is invalid / not pending. */
  fillPending(token: string, plaintext: string): string | null {
    const entry = this.resolveInputToken(token);
    if (!entry) return null;
    const clean = entry.name;
    const key = this.getKey();
    writeFileSync(join(BLOBS_DIR(), `${clean}.enc`), encrypt(plaintext, key), { mode: 0o600 });
    const secrets = readJson<Record<string, SecretMeta>>(SECRETS_FILE());
    secrets[clean] = {
      ...secrets[clean],
      pending: false,
      inputToken: undefined,
      inputTokenIssuedAt: undefined,
      sha256: createHash('sha256').update(plaintext).digest('hex'),
    };
    writeJson(SECRETS_FILE(), secrets);
    return clean;
  }

  /** Create a new pending secret with a fresh input token. Returns
   *  the input token. If a secret with this name already exists (pending
   *  or not), returns its existing inputToken so a second agent call
   *  yields the same URL instead of leaking that the secret exists. */
  requestPending(name: string): { token: string; fresh: boolean } {
    const clean = sanitizeName(name);
    const secrets = readJson<Record<string, SecretMeta>>(SECRETS_FILE());
    const existing = secrets[clean];
    if (existing?.pending && existing.inputToken) {
      return { token: existing.inputToken, fresh: false };
    }
    const token = randomBytes(32).toString('base64url'); // 256-bit
    secrets[clean] = {
      ...existing,
      sha256: existing?.sha256 ?? '',
      created: existing?.created ?? new Date().toISOString(),
      pending: true,
      inputToken: token,
      inputTokenIssuedAt: new Date().toISOString(),
    };
    writeJson(SECRETS_FILE(), secrets);
    return { token, fresh: true };
  }

  /* ---- agents (age public keys) ---- */

  registerAgent(agent_id: string, publicKey: string, label?: string): AgentKey {
    if (!publicKey.startsWith('age1')) throw new Error('publicKey must start with age1');
    ensureDirs();
    const agents = readJson<Record<string, AgentKey>>(AGENTS_FILE());
    const now = new Date().toISOString();
    const entry: AgentKey = {
      agent_id,
      publicKey,
      registered: agents[agent_id]?.registered ?? now,
      lastSeen: now,
      label,
    };
    agents[agent_id] = entry;
    writeJson(AGENTS_FILE(), agents);
    return entry;
  }

  getAgent(agent_id: string): AgentKey | null {
    return readJson<Record<string, AgentKey>>(AGENTS_FILE())[agent_id] ?? null;
  }

  listAgents(): AgentKey[] {
    return Object.values(readJson<Record<string, AgentKey>>(AGENTS_FILE()));
  }

  /** Encrypt a stored secret for a registered agent's age public key.
   *  Returns ASCII-armored age ciphertext. Throws if agent not registered
   *  or secret not ready. */
  async encryptForAgent(agent_id: string, name: string): Promise<string> {
    const agent = this.getAgent(agent_id);
    if (!agent) throw new Error('agent not registered');
    const entry = this.getSecret(name);
    if (!entry) throw new Error('secret not found or pending');
    return encryptForRecipient(decrypt(entry.blob, this.getKey()), agent.publicKey);
  }
}
