#!/usr/bin/env node
// sss-get — fetch a secret from SSS via MCP and decrypt it with the
// agent's age private key. Outputs plaintext to stdout.
//
// First run: generates an X25519 age identity under
//   ~/.config/sss-mcp/agent-identity.json (chmod 600)
// Registers the public key with SSS via MCP register_agent (one-time).
//
// Usage:
//   SSS_API_KEY=... sss-get <name>            # to stdout
//   SSS_API_KEY=... sss-get <name> | <cmd>    # pipe to a command
//
// Env:
//   SSS_API_KEY  — Bearer token (required)
//   SSS_URL      — server base URL (default https://pswd.bezrabotnyi.com)
//   SSS_AGENT_ID — agent id (default: sss-agent-<hostname>)
//   SSS_AGENT_LABEL — human label for registration

import { generateX25519Identity, identityToRecipient, Decrypter, armor } from 'age-encryption';
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { hostname } from 'node:os';

const SSS_URL = process.env.SSS_URL || 'https://pswd.bezrabotnyi.com';
let API_KEY = process.env.SSS_API_KEY;
if (!API_KEY) {
  // Fall back to the private env file used by systemd / login shell.
  try {
    const envPath = join(process.env.HOME, '.config', 'sss-mcp', 'api-key.env');
    if (existsSync(envPath)) {
      API_KEY = readFileSync(envPath, 'utf8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l.startsWith('SSS_API_KEY='))
        .map(l => l.slice('SSS_API_KEY='.length))[0];
    }
  } catch {}
}
if (!API_KEY) {
  console.error('SSS_API_KEY env var required (or ~/.config/sss-mcp/api-key.env)');
  process.exit(2);
}
const AGENT_ID = process.env.SSS_AGENT_ID || `sss-agent-${hostname()}`;
const AGENT_LABEL = process.env.SSS_AGENT_LABEL || `codex@${hostname()}`;
const NAME = process.argv[2];
if (!NAME) { console.error('usage: sss-get <name>'); process.exit(2); }

const IDENTITY_DIR = join(process.env.HOME, '.config', 'sss-mcp');
const IDENTITY_PATH = join(IDENTITY_DIR, 'agent-identity.json');

function loadIdentity() {
  if (!existsSync(IDENTITY_PATH)) {
    mkdirSync(IDENTITY_DIR, { recursive: true, mode: 0o700 });
    return null;
  }
  chmodSync(IDENTITY_PATH, 0o600);
  return JSON.parse(readFileSync(IDENTITY_PATH, 'utf8'));
}

async function ensureIdentity() {
  let id = loadIdentity();
  if (id) return id;
  // Generate a fresh X25519 identity.
  const secretKey = await generateX25519Identity();
  const publicKey = await identityToRecipient(secretKey);
  id = { agent_id: AGENT_ID, secretKey, publicKey, created: new Date().toISOString() };
  writeFileSync(IDENTITY_PATH, JSON.stringify(id, null, 2));
  chmodSync(IDENTITY_PATH, 0o600);
  return id;
}

async function mcp(method, params, sid) {
  const headers = {
    'Authorization': `Bearer ${API_KEY}`,
    'Content-Type': 'application/json',
    'Accept': 'application/json, text/event-stream',
  };
  if (sid) headers['Mcp-Session-Id'] = sid;
  const r = await fetch(`${SSS_URL}/mcp`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ jsonrpc: '2.0', id: Math.floor(Math.random() * 1e9), method, params: params ?? {} }),
  });
  const text = await r.text();
  return { sid: r.headers.get('mcp-session-id') || sid, text, status: r.status };
}

function parseSse(text) {
  const m = text.match(/^data: (.+)$/m);
  return m ? JSON.parse(m[1]) : JSON.parse(text);
}

async function ensureRegistered(id) {
  // Try a register_agent call — server is idempotent (returns existing).
  const init = await mcp('initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'sss-get', version: '0.1.0' },
  });
  const sid = init.sid;
  await mcp('notifications/initialized', {}, sid);
  const reg = await mcp('tools/call', {
    name: 'register_agent',
    arguments: { agent_id: AGENT_ID, public_key: id.publicKey, label: AGENT_LABEL },
  }, sid);
  const regResp = parseSse(reg.text);
  if (regResp.result?.isError) {
    console.error('register_agent failed:', regResp.result?.content?.[0]?.text);
    process.exit(1);
  }
  return sid;
}

const id = await ensureIdentity();
const sid = await ensureRegistered(id);

const callResp = await mcp('tools/call', {
  name: 'get_secret',
  arguments: { name: NAME, agent_id: AGENT_ID },
}, sid);
const callJson = parseSse(callResp.text);
const text = callJson.result?.content?.[0]?.text ?? '';
if (callJson.result?.isError) {
  console.error(text);
  process.exit(1);
}

const dUrl = (text.match(/https?:\/\/[^\s]+\/d\/[a-f0-9]{32}/) || [])[0];
if (!dUrl) {
  // No /d/ URL — probably not_found or pending. Surface the MCP text.
  process.stderr.write(text + '\n');
  process.exit(3);
}

const cipherRes = await fetch(dUrl);
if (!cipherRes.ok) {
  console.error(`fetch /d/ failed: HTTP ${cipherRes.status}`);
  process.exit(1);
}
const cipher = await cipherRes.text();
if (cipherRes.headers.get('content-type')?.startsWith('application/vnd.age')) {
  // E2E age path
  const dec = new Decrypter();
  dec.addIdentity(id.secretKey);
  const plain = await dec.decrypt(armor.decode(cipher), 'text');
  process.stdout.write(plain);
} else {
  // base64 fallback (SSS sees plaintext)
  const plain = Buffer.from(cipher, 'base64').toString('utf8');
  process.stdout.write(plain);
}