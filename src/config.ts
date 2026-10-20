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

/* ================================================================
   SSO IDENTITY (reverse proxy)
   The front-end proxy verifies the auth.bezrabotnyi.com cookie and
   then overwrites two headers on the request it forwards to SSS.
   SSS trusts the identity only when both are present and valid.
   ================================================================ */

/** Header that marks a request as coming through the trusted front
 *  end. The proxy must always overwrite it — a client-supplied value
 *  must never survive the hop. */
export const TRUSTED_PROXY_HEADER = 'x-sss-trusted-proxy';

/** Exact value the proxy must put into TRUSTED_PROXY_HEADER. */
export const TRUSTED_PROXY_VALUE = '1';

/** Header that carries the user name verified by the cookie auth
 *  service. The proxy must overwrite it with the value returned by the
 *  auth check, never with the client's own header. */
export const SSO_USER_HEADER = 'x-gptadmin-user';

/** Where the browser is sent to sign in / sign out. Overridable for
 *  deployments that use a different auth front end. */
export const SSO_LOGIN_URL = () =>
  process.env.SSS_SSO_LOGIN_URL ?? 'https://auth.bezrabotnyi.com/login';
export const SSO_LOGOUT_URL = () =>
  process.env.SSS_SSO_LOGOUT_URL ?? 'https://auth.bezrabotnyi.com/logout';

/** Validate an identity header value. Only a conservative character
 *  set is accepted, so the value can never inject a header, a log
 *  line, or markup. Returns null when the value is not a usable
 *  identity — the caller then fails closed. */
export function sanitizeIdentity(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const clean = value.trim();
  if (!clean || clean.length > 128) return null;
  if (!/^[A-Za-z0-9._@-]+$/.test(clean)) return null;
  return clean;
}
