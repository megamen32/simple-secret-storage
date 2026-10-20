import {
  readFileSync, writeFileSync, unlinkSync, existsSync, copyFileSync,
  openSync, closeSync, fsyncSync, renameSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
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
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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
  /** Opaque owner correlation ID for the optional completion callback. */
  requestId?: string;
}

/** Outcome of a rename request. */
export type RenameSecretResult =
  | { status: 'renamed'; from: string; to: string }
  | { status: 'not_found' }
  | { status: 'conflict' }
  | { status: 'invalid'; message: string };

export interface PendingFillResult {
  name: string;
  requestId?: string;
}

/** Meta as it may leave the process over the API.
 *
 *  `inputToken` is a one-time bearer capability: it opens the /i/<token>
 *  form for a pending secret. It must never be serialized into an API
 *  response, otherwise listing the store hands the caller the ability
 *  to overwrite a pending value. `sha256` is dropped for the same
 *  reason class — it is a verifier of the plaintext, which would turn
 *  the list endpoint into an offline guessing oracle.
 *
 *  `pending` and `requestId` are kept: they carry status and request
 *  correlation without being usable as a credential. */
export interface PublicSecretMeta {
  description?: string;
  url?: string;
  account?: string;
  created: string;
  pending?: boolean;
  requestId?: string;
}

/** Strip token-only and verifier fields from a stored meta. */
export function publicSecretMeta(meta: SecretMeta): PublicSecretMeta {
  return {
    description: meta.description,
    url: meta.url,
    account: meta.account,
    created: meta.created,
    pending: meta.pending,
    requestId: meta.requestId,
  };
}

function readJson<T = Record<string, any>>(path: string): T {
  if (!existsSync(path)) return Object.create(null) as T;
  const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Expected a JSON object in ${path}`);
  }
  // These maps use user-controlled names as keys. A plain object would
  // interpret keys such as "__proto__" through Object.prototype.
  return Object.assign(Object.create(null), parsed) as T;
}

function writeJson(path: string, data: Record<string, any>): void {
  const dir = dirname(path);
  const temp = join(dir, `.${randomUUID()}.tmp`);
  let fd: number | undefined;
  try {
    fd = openSync(temp, 'wx', 0o600);
    writeFileSync(fd, JSON.stringify(data, null, 2) + '\n', 'utf8');
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, path);
    const dirFd = openSync(dir, 'r');
    try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    if (existsSync(temp)) unlinkSync(temp);
    throw error;
  }
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

  /** List stored secrets with redacted metadata. The raw meta — and
   *  with it the one-time input token — stays inside the process. */
  listSecrets(): Array<{ name: string; meta: PublicSecretMeta }> {
    const secrets = readJson<Record<string, SecretMeta>>(SECRETS_FILE());
    return Object.entries(secrets).map(([name, meta]) => ({ name, meta: publicSecretMeta(meta) }));
  }

  /** Rename a secret without touching its value.
   *
   *  The encrypted blob is copied to the new name before the metadata
   *  is switched and the old blob is removed afterwards, so an
   *  interrupted rename never loses the stored value. */
  renameSecret(from: string, to: string): RenameSecretResult {
    let source: string;
    let target: string;
    try {
      source = sanitizeName(from);
      target = sanitizeName(to);
    } catch (e: any) {
      return { status: 'invalid', message: e?.message ?? 'invalid secret name' };
    }
    if (source === target) return { status: 'renamed', from: source, to: target };

    const secrets = readJson<Record<string, SecretMeta>>(SECRETS_FILE());
    if (!Object.prototype.hasOwnProperty.call(secrets, source)) return { status: 'not_found' };
    if (Object.prototype.hasOwnProperty.call(secrets, target)) return { status: 'conflict' };

    const sourceBlob = join(BLOBS_DIR(), `${source}.enc`);
    const targetBlob = join(BLOBS_DIR(), `${target}.enc`);
    if (existsSync(targetBlob)) return { status: 'conflict' };
    if (existsSync(sourceBlob)) {
      copyFileSync(sourceBlob, targetBlob);
      const targetFd = openSync(targetBlob, 'r');
      try { fsyncSync(targetFd); } finally { closeSync(targetFd); }
      const dirFd = openSync(dirname(targetBlob), 'r');
      try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
    }

    const meta = secrets[source];
    delete secrets[source];
    Object.defineProperty(secrets, target, {
      value: { ...meta },
      enumerable: true,
      configurable: true,
      writable: true,
    });
    writeJson(SECRETS_FILE(), secrets);

    if (existsSync(sourceBlob)) {
      unlinkSync(sourceBlob);
      const dirFd = openSync(dirname(sourceBlob), 'r');
      try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
    }
    return { status: 'renamed', from: source, to: target };
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
  fillPending(token: string, plaintext: string): PendingFillResult | null {
    const entry = this.resolveInputToken(token);
    if (!entry) return null;
    const clean = entry.name;
    const requestId = entry.meta.requestId;
    const key = this.getKey();
    writeFileSync(join(BLOBS_DIR(), `${clean}.enc`), encrypt(plaintext, key), { mode: 0o600 });
    const secrets = readJson<Record<string, SecretMeta>>(SECRETS_FILE());
    secrets[clean] = {
      ...secrets[clean],
      pending: false,
      inputToken: undefined,
      inputTokenIssuedAt: undefined,
      requestId: undefined,
      sha256: createHash('sha256').update(plaintext).digest('hex'),
    };
    writeJson(SECRETS_FILE(), secrets);
    return { name: clean, requestId };
  }

  /** Create a new pending secret with a fresh input token. Returns
   *  the input token. If a secret with this name already exists (pending
   *  or not), returns its existing inputToken so a second agent call
   *  yields the same URL instead of leaking that the secret exists. */
  requestPending(name: string, requestId?: string): { token: string; fresh: boolean; requestId?: string } {
    if (requestId !== undefined && !UUID.test(requestId)) {
      throw new Error('requestId must be an opaque UUID');
    }
    const clean = sanitizeName(name);
    const secrets = readJson<Record<string, SecretMeta>>(SECRETS_FILE());
    const existing = secrets[clean];
    if (existing?.pending && existing.inputToken) {
      return { token: existing.inputToken, fresh: false, requestId: existing.requestId };
    }
    const token = randomBytes(32).toString('base64url'); // 256-bit
    secrets[clean] = {
      ...existing,
      sha256: existing?.sha256 ?? '',
      created: existing?.created ?? new Date().toISOString(),
      pending: true,
      inputToken: token,
      inputTokenIssuedAt: new Date().toISOString(),
      requestId: requestId ?? randomUUID(),
    };
    writeJson(SECRETS_FILE(), secrets);
    return { token, fresh: true, requestId: secrets[clean].requestId };
  }

  /* ---- agents (age public keys) ---- */

  registerAgent(agent_id: string, publicKey: string, label?: string): AgentKey {
    if (!publicKey.startsWith('age1')) throw new Error('publicKey must start with age1');
    ensureDirs();
    const agents = readJson<Record<string, AgentKey>>(AGENTS_FILE());
    const existing = agents[agent_id];
    if (existing && existing.publicKey !== publicKey) {
      throw new Error(`agent identity "${agent_id}" cannot be replaced`);
    }
    const now = new Date().toISOString();
    const entry: AgentKey = {
      agent_id,
      publicKey,
      registered: existing?.registered ?? now,
      lastSeen: now,
      label: label ?? existing?.label,
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
