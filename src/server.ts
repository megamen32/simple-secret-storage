import express, { Request, Response, NextFunction } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { randomBytes, randomUUID } from 'node:crypto';
import { Storage, SecretMeta } from './storage.js';
import {
  ensureDirs,
  BLOBS_DIR,
  TRUSTED_PROXY_HEADER,
  TRUSTED_PROXY_VALUE,
  SSO_USER_HEADER,
  SSO_LOGIN_URL,
  SSO_LOGOUT_URL,
  sanitizeIdentity,
} from './config.js';
import { buildCompletionEvent, getCompletionCallback, postCompletion } from './completion-callback.js';
import { createRuntimeOperations, registerAskSecretTools, secretRequestName } from './ask-secret-tools.js';

/* ================================================================
   ENV
   ================================================================ */
const PORT = Number(process.env.SSS_PORT ?? '8743');
const API_KEY = process.env.SSS_API_KEY;
if (!API_KEY) {
  console.error('SSS_API_KEY env var is required (64-bit hex, 16 chars).');
  process.exit(1);
}
const SERVER_URL = process.env.SSS_SERVER_URL ?? `http://127.0.0.1:${PORT}`;
const COMPLETION_CALLBACK = getCompletionCallback();

/* ================================================================
   STORAGE
   ================================================================ */
const storage = new Storage();

/* One-time decrypt tokens: token → { name, expires } */
const dTokens = new Map<string, { name: string; expires: number; encoding?: 'age' | 'base64'; agentId?: string }>();
function cleanupTokens(): void {
  const now = Date.now();
  for (const [t, v] of dTokens) if (v.expires < now) dTokens.delete(t);
}
setInterval(cleanupTokens, 60_000);

/* ================================================================
   EXPRESS
   ================================================================ */
const app = express();

/* The SDK transport takes the already parsed JSON body. */
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

/* ================================================================
   AUTH
   Two accepted credentials:
     1. Bearer <SSS_API_KEY> — MCP clients and API clients.
     2. SSO identity — the reverse proxy verifies the
        auth.bezrabotnyi.com cookie and overwrites two headers:
        a trusted-proxy marker and the verified user name.
   Both SSO headers must be present and valid; anything else fails
   closed with 401.
   ================================================================ */

/** The verified SSO user for this request, or null when the request
 *  carries no trusted proxy identity. */
function ssoIdentity(req: Request): string | null {
  const marker = req.headers[TRUSTED_PROXY_HEADER];
  if (marker !== TRUSTED_PROXY_VALUE) return null;
  return sanitizeIdentity(req.headers[SSO_USER_HEADER]);
}

type SessionMode = 'bearer' | 'sso';

/** How this request is authenticated. Only meaningful after `auth`. */
function sessionFor(req: Request): { mode: SessionMode; user?: string } {
  const user = ssoIdentity(req);
  if (user) return { mode: 'sso', user };
  return { mode: 'bearer' };
}

/** Mutating SSO requests must originate from this proxied HTTPS origin.
 *  The reverse proxy overwrites these forwarding headers after validating
 *  the shared SSO cookie, so sibling subdomains cannot forge the target. */
function isSameSsoOrigin(req: Request): boolean {
  const originHeader = req.get('origin');
  const protoHeader = req.get('x-forwarded-proto');
  const hostHeader = req.get('x-forwarded-host');
  if (!originHeader || !protoHeader || !hostHeader) return false;
  const proto = protoHeader.split(',')[0].trim().toLowerCase();
  const host = hostHeader.split(',')[0].trim().toLowerCase();
  if (proto !== 'https' || !host) return false;
  try {
    return new URL(originHeader).origin === `https://${host}`;
  } catch {
    return false;
  }
}

function auth(req: Request, res: Response, next: NextFunction): void {
  if (req.headers.authorization === `Bearer ${API_KEY}`) {
    next();
    return;
  }
  if (ssoIdentity(req)) {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !isSameSsoOrigin(req)) {
      res.status(403).json({ error: 'same-origin request required' });
      return;
    }
    next();
    return;
  }
  res.status(401).json({ error: 'unauthorized' });
}

/* ================================================================
   MCP SERVER (Streamable HTTP)
   ================================================================ */
/* ---- Mount MCP on Express ---- */
// All durable handoff state belongs to Storage. The MCP connection has no
// subscriptions or per-client state: the SDK's stateless JSON transport avoids
// stale session IDs after a service restart and unnecessary long-lived SSE.

function makeServer(): McpServer {
  const s = new McpServer({ name: 'ask-secret', version: '1.0.0' });
  const runtimeOperations = createRuntimeOperations();
  registerAskSecretTools(s, {
    ...runtimeOperations,
    async probeSecret({ name, request_id }) {
      const meta = storage.getSecretMeta(name);
      if (!meta || meta.pending) {
        const {token, requestId} = storage.requestPending(name, request_id);
        return {status: 'pending', name, input_url: `${SERVER_URL}/i/${token}`, request_id: requestId};
      }
      return { status: 'ready', name };
    },
  });
  s.tool(
    'get_secret',
    'Request a secret; name is optional and generated automatically. For a browser form prefer ask_secret, which never returns download URLs. If found, returns the path to an AES-encrypted blob file ' +
      'on disk plus a one-time URL to fetch it. The LLM must pipe the file contents ' +
      'into its target command — NEVER read or display the file (it is opaque bytes). ' +
      'If not found, tells the agent to ask the user to create it via the web UI.',
    { name: z.string().optional().describe('Optional secret name; generated automatically if omitted'),
      agent_id: z.string().optional().describe('Agent ID registered via register_agent. If provided, the value is encrypted with the agent\'s age public key (true E2E); otherwise it is returned as base64 (SSS sees the plaintext).'),
      request_id: z.string().uuid().optional().describe('Opaque Human Request owner ID used only for completion correlation.') },
    async ({ name: suppliedName, agent_id, request_id }) => {
      const name = secretRequestName(suppliedName, request_id);
      const meta = storage.getSecretMeta(name);
      // Pending = user hasn't entered the value yet. Surface the
      // user-input URL so the agent forwards it again.
      if (!meta || meta.pending) {
        const { token, fresh, requestId } = storage.requestPending(name, request_id);
        return {
          content: [{
            type: 'text' as const,
            text:
              (meta?.pending
                ? `Secret "${name}" is pending user input.\n`
                : `Secret "${name}" not found.\n`) +
              `${fresh ? 'Send the user this one-time URL' : 'Re-send the same one-time URL'} to enter the value:\n` +
              `  ${SERVER_URL}/i/${token}\n\n` +
              `Opaque request_id: ${requestId ?? '(not available for this legacy pending request)'}\n` +
              `After the user submits, call get_secret("${name}") again to receive the encrypted blob URL.`,
          }],
        };
      }
      const token = randomBytes(16).toString('hex');
      dTokens.set(token, {
        name,
        expires: Date.now() + 5 * 60_000,
        encoding: agent_id ? 'age' : 'base64',
        agentId: agent_id,
      });
      const blobPath = `${BLOBS_DIR()}/${name}.enc`;
      const hint = agent_id
        ? `curl -sL '${SERVER_URL}/d/${token}' | age --decrypt | <your-command>`
        : `curl -sL '${SERVER_URL}/d/${token}' | base64 -d | <your-command>`;
      const note = agent_id
        ? `\nEncrypted for agent_id="${agent_id}" with age (X25519). Only your identity can decrypt.`
        : `\nWARNING: returned as base64. SSS sees the plaintext. To get true E2E encryption, register with register_agent() and pass agent_id here.`;
      return {
        content: [{
          type: 'text' as const,
          text:
            `Secret "${name}" is stored as an encrypted blob on disk.\n` +
            `Disk path: ${blobPath}\n` +
            `One-time fetch URL (5 min, single use): ${SERVER_URL}/d/${token}\n` +
            note + '\n\n' +
            `Pipe directly into your command. Do NOT read or display the ciphertext.\n` +
            `  ${hint}\n`,
        }],
      };
    },
  );

  s.tool(
    'list_secrets',
    'List all stored secret names with their metadata (no values).',
    {},
    async () => {
      const list = storage.listSecrets();
      if (!list.length) return { content: [{ type: 'text' as const, text: '(no secrets)' }] };
      const lines = list.map(s => `${s.name}  ${s.meta.description ?? ''}  ${s.meta.account ?? ''}  ${s.meta.url ?? ''}`.trim());
      return { content: [{ type: 'text' as const, text: lines.join('\n') }] };
    },
  );

  s.tool(
    'register_agent',
    'Register an age (X25519) public key for end-to-end encrypted secret delivery. ' +
      'Generate a fresh identity on the agent side, call this with the public key, then ' +
      'pass agent_id to get_secret() so the value is encrypted with your public key and ' +
      'only your private key can decrypt it.',
    {
      agent_id: z.string().describe('A unique identifier for this agent (e.g. "codex-laptop1", "claude-cli-2026-08").'),
      public_key: z.string().describe('age public key, must start with "age1".'),
      label: z.string().optional().describe('Human-readable label for this agent.'),
    },
    async ({ agent_id, public_key, label }) => {
      try {
        const entry = storage.registerAgent(agent_id, public_key, label);
        return {
          content: [{
            type: 'text' as const,
            text:
              `Agent "${agent_id}" registered.\n` +
              `Public key: ${entry.publicKey}\n` +
              `Registered: ${entry.registered}\n\n` +
              `Pass agent_id="${agent_id}" to get_secret() to receive values encrypted with your public key. ` +
              `Decrypt on the agent side with your private key (AGE-SECRET-KEY-1...).`,
          }],
        };
      } catch (e: any) {
        return {
          content: [{ type: 'text' as const, text: `register_agent failed: ${e?.message ?? e}` }],
          isError: true,
        };
      }
    },
  );

  s.tool(
    'delete_secret',
    'Delete a secret by name.',
    { name: z.string().describe('Secret name to delete') },
    async ({ name }) => {
      const ok = storage.deleteSecret(name);
      return { content: [{ type: 'text' as const, text: ok ? `Deleted "${name}".` : `Not found: "${name}".` }] };
    },
  );

  s.tool(
    'rename_secret',
    'Rename a secret. The stored value is never read, returned, or changed — ' +
      'only the name it is stored under. Use it to give an auto-generated ' +
      'secret a meaningful name. Returns the effective (sanitized) name.',
    {
      name: z.string().describe('Current secret name'),
      new_name: z.string().describe('New secret name'),
    },
    async ({ name, new_name }) => {
      const result = storage.renameSecret(name, new_name);
      if (result.status === 'renamed') {
        return {
          content: [{
            type: 'text' as const,
            text: `Renamed "${result.from}" to "${result.to}". The value was not read or changed.`,
          }],
        };
      }
      if (result.status === 'not_found') {
        return { content: [{ type: 'text' as const, text: `Not found: "${name}".` }] };
      }
      if (result.status === 'conflict') {
        return { content: [{ type: 'text' as const, text: `Cannot rename to "${new_name}": that name already exists.` }] };
      }
      return { content: [{ type: 'text' as const, text: `rename_secret failed: ${result.message}` }], isError: true };
    },
  );
  return s;
}

app.all('/mcp', async (req: any, res: any, next: NextFunction) => {
  if (req.headers.authorization !== `Bearer ${API_KEY}`) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    res.status(405).end();
    return;
  }
  const server = makeServer();
  const transport = new StreamableHTTPServerTransport({sessionIdGenerator: undefined, enableJsonResponse: true});
  res.on('close', () => { void transport.close(); void server.close(); });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e: any) {
    console.error('[mcp] request failed');
    if (!res.headersSent) res.status(500).json({ error: 'internal error' });
  }
});

/* ================================================================
   REST API  (/api/*)
   ================================================================ */

/* Which credential this request authenticated with. The web UI uses it
   to decide between the SSO session and the bearer token form. */
app.get('/api/session', auth, (req: Request, res: Response) => {
  const session = sessionFor(req);
  res.json({ mode: session.mode, user: session.user ?? null });
});

app.get('/api/secrets', auth, (_req: Request, res: Response) => {
  res.json({ secrets: storage.listSecrets() });
});

app.post('/api/secrets', auth, (req: Request, res: Response) => {
  const { name, value, description, url, account } = req.body;
  if (!name || typeof name !== 'string') { res.status(400).json({ error: 'name required' }); return; }
  if (!value || typeof value !== 'string') { res.status(400).json({ error: 'value required' }); return; }
  try {
    storage.saveSecret(name, value, { description, url, account });
    res.json({ ok: true, name });
  } catch (e: any) {
    res.status(400).json({ error: e.message });
  }
});

app.put('/api/secrets/:name', auth, (req: Request, res: Response) => {
  const { description, url, account } = req.body;
  const ok = storage.updateMeta(req.params.name as string, { description, url, account });
  res.json({ ok });
});

/* Rename a secret. The stored value is never read, returned, or
   changed — only the name it is stored under. */
app.post('/api/secrets/:name/rename', auth, (req: Request, res: Response) => {
  const target = req.body?.name;
  if (typeof target !== 'string' || !target.trim()) {
    res.status(400).json({ error: 'name required' });
    return;
  }
  const result = storage.renameSecret(req.params.name as string, target);
  if (result.status === 'not_found') {
    res.status(404).json({ error: 'not found' });
    return;
  }
  if (result.status === 'conflict') {
    res.status(409).json({ error: 'name already exists' });
    return;
  }
  if (result.status === 'invalid') {
    res.status(400).json({ error: result.message });
    return;
  }
  /* One-time decrypt URLs issued before the rename still point at the
     old name — retarget them so they keep working. */
  for (const entry of dTokens.values()) {
    if (entry.name === result.from) entry.name = result.to;
  }
  res.json({ ok: true, name: result.to, renamed_from: result.from });
});

app.delete('/api/secrets/:name', auth, (req: Request, res: Response) => {
  const ok = storage.deleteSecret(req.params.name as string);
  if (!ok) { res.status(404).json({ error: 'not found' }); return; }
  res.json({ ok: true });
});

/* ================================================================
   ONE-TIME DECRYPT  /d/<token>
   No Bearer needed — the token itself is the credential.

   Returns the secret as base64(text/plain) so the agent can pipe it
   directly into its target command:
       curl -sL '…/d/<token>' | base64 -d | <your-command>
   The LLM never sees the plaintext; only base64-opaque bytes.
   ================================================================ */

app.get('/d/:token', async (req: Request, res: Response) => {
  const entry = dTokens.get(req.params.token as string);
  if (!entry || Date.now() > entry.expires) {
    res.status(410).send('Token expired or not found');
    return;
  }
  dTokens.delete(req.params.token as string);
  if (entry.encoding === 'age' && entry.agentId) {
    try {
      const cipher = await storage.encryptForAgent(entry.agentId, entry.name);
      res.set('Content-Type', 'application/vnd.age');
      res.set('X-SSS-Encoding', 'age');
      res.send(cipher);
    } catch (e: any) {
      res.status(500).send(`encrypt-for-agent failed: ${e?.message ?? e}`);
    }
    return;
  }
  const plaintext = storage.decryptSecret(entry.name);
  if (plaintext === null) { res.status(404).send('Secret not found'); return; }
  res.set('Content-Type', 'text/plain; charset=utf-8');
  res.set('X-SSS-Encoding', 'base64');
  res.send(Buffer.from(plaintext, 'utf8').toString('base64'));
});

/* ================================================================
   PASSWORDLESS SECRET CREATION  /secret
   No Bearer or access password is required. The server generates an
   opaque ID, stores the submitted value encrypted, and returns only
   that ID to the browser.
   ================================================================ */

app.get('/secret', (_req: Request, res: Response) => {
  sendSecretHtml(res, 200, publicSecretFormHtml());
});

app.post('/secret', (req: Request, res: Response) => {
  const value = typeof req.body?.value === 'string' ? req.body.value : '';
  if (!value) {
    sendSecretHtml(res, 400, publicSecretFormHtml('Please enter a non-empty value.'));
    return;
  }
  if (value.length > 64 * 1024) {
    sendSecretHtml(res, 413, publicSecretFormHtml('Value is too large.'));
    return;
  }

  let id = randomUUID();
  while (storage.getSecretMeta(id)) id = randomUUID();
  storage.saveSecret(id, value);
  sendSecretHtml(res, 201, publicSecretSavedHtml(id));
});

function sendSecretHtml(res: Response, status: number, html: string): void {
  res.set('Cache-Control', 'no-store');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('X-Content-Type-Options', 'nosniff');
  res.status(status).type('html').send(html);
}

function publicSecretFormHtml(error?: string): string {
  return `<!doctype html>
<html lang=en>
<head>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>SSS — Add secret</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;margin:0}
  .wrap{max-width:420px;margin:6rem auto;padding:2rem;background:#161616;border:1px solid #333;border-radius:12px}
  h1{font-size:1.2rem;margin:0 0 .4rem}
  .sub,.hint{color:#888;font-size:.8rem;line-height:1.45}.sub{margin-bottom:1.5rem}.hint{margin-top:1rem}
  .error{color:#fca5a5;background:#3b1111;border:1px solid #7f1d1d;border-radius:6px;padding:.65rem .8rem;margin-bottom:1rem;font-size:.8rem}
  label{display:block;font-size:.75rem;color:#aaa;margin-bottom:.3rem}
  input{width:100%;padding:.65rem .8rem;border:1px solid #333;border-radius:6px;background:#1a1a1a;color:#e0e0e0;font-size:.95rem;font-family:inherit;box-sizing:border-box}
  input:focus{outline:none;border-color:#2563eb}
  button{margin-top:1rem;width:100%;padding:.65rem;background:#2563eb;color:#fff;border:none;border-radius:6px;font-size:.9rem;cursor:pointer;font-family:inherit}
  button:hover{background:#1d4ed8}
</style>
</head>
<body>
<form class=wrap method=post action="/secret" autocomplete=off>
  <h1>Add secret</h1>
  <div class=sub>No account or access password required. You will receive an opaque ID.</div>
  ${error ? `<div class=error role=alert>${escapeHtml(error)}</div>` : ''}
  <label for=value>Secret value</label>
  <input id=value type=password name=value placeholder="secret value" autofocus required>
  <button type=submit>Save and get ID</button>
  <div class=hint>The value is sent over HTTPS and stored encrypted with AES-256-GCM.</div>
</form>
</body>
</html>`;
}

function publicSecretSavedHtml(id: string): string {
  return `<!doctype html>
<html lang=en>
<head>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>SSS — Secret saved</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;margin:0}
  .wrap{max-width:520px;margin:6rem auto;padding:2rem;background:#161616;border:1px solid #333;border-radius:12px}
  h1{font-size:1.2rem;margin:0 0 1rem}.label{color:#888;font-size:.8rem;margin-bottom:.35rem}
  code{display:block;overflow-wrap:anywhere;background:#222;padding:.8rem;border-radius:6px;color:#bfdbfe;font-size:1rem;user-select:all}
  p{color:#888;font-size:.8rem;line-height:1.45;margin:1rem 0 0}a{color:#60a5fa}
</style>
</head>
<body>
<main class=wrap>
  <h1>Secret saved</h1>
  <div class=label>Secret ID</div>
  <code id="secret-id">${escapeHtml(id)}</code>
  <p>Copy this ID now. The secret value is not shown again.</p>
  <p><a href="/secret">Add another secret</a></p>
</main>
</body>
</html>`;
}

/* ================================================================
   ANONYMOUS INPUT FORM  /i/<token>  +  /submit/<token>
   No Bearer needed — the input token is the credential. The token
   is a one-time 256-bit secret created by get_secret when the agent
   asks for a value the user hasn't entered yet.
   ================================================================ */

app.get('/i/:token', (req: Request, res: Response) => {
  const entry = storage.resolveInputToken(req.params.token as string);
  if (!entry) {
    res.status(410).type('html').send(
      '<!doctype html><meta charset=utf-8><title>SSS</title>' +
      '<body style="font-family:sans-serif;max-width:480px;margin:4rem auto;color:#444">' +
      '<h2>Link expired</h2><p>This one-time link is no longer valid.</p></body>',
    );
    return;
  }
  res.type('html').send(inputFormHtml(entry.name, req.params.token as string));
});

app.post('/submit/:token', (req: Request, res: Response) => {
  const token = req.params.token as string;
  const value = typeof req.body?.value === 'string' ? req.body.value : '';
  if (!value) {
    res.status(400).type('html').send(
      '<!doctype html><meta charset=utf-8><title>SSS</title>' +
      '<body style="font-family:sans-serif;max-width:480px;margin:4rem auto;color:#444">' +
      '<h2>Empty value</h2><p>Please enter a non-empty value.</p></body>',
    );
    return;
  }
  if (value.length > 64 * 1024) {
    res.status(413).send('Value too large');
    return;
  }
  const filled = storage.fillPending(token, value);
  if (!filled) {
    res.status(410).type('html').send(
      '<!doctype html><meta charset=utf-8><title>SSS</title>' +
      '<body style="font-family:sans-serif;max-width:480px;margin:4rem auto;color:#444">' +
      '<h2>Link expired</h2><p>This one-time link is no longer valid.</p></body>',
    );
    return;
  }
  if (COMPLETION_CALLBACK && filled.requestId) {
    const event = buildCompletionEvent(filled.requestId, randomUUID());
    void postCompletion(COMPLETION_CALLBACK, event);
  }
  res.type('html').send(
    '<!doctype html><meta charset=utf-8><title>SSS</title>' +
    '<body style="font-family:sans-serif;max-width:480px;margin:4rem auto;color:#444">' +
    '<h2>Saved</h2><p>Value for <code>' + escapeHtml(filled.name) + '</code> has been stored encrypted. ' +
    'You can close this tab.</p></body>',
  );
});

function inputFormHtml(name: string, token: string): string {
  return `<!doctype html>
<html lang=en>
<head>
<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>SSS — Enter value for ${escapeHtml(name)}</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh;margin:0}
  .wrap{max-width:420px;margin:6rem auto;padding:2rem;background:#161616;border:1px solid #333;border-radius:12px}
  h1{font-size:1.2rem;margin:0 0 .25rem}
  .sub{color:#888;font-size:.85rem;margin-bottom:1.5rem}
  code{background:#222;padding:.1rem .35rem;border-radius:3px;color:#bbb}
  input{width:100%;padding:.65rem .8rem;border:1px solid #333;border-radius:6px;background:#1a1a1a;color:#e0e0e0;font-size:.95rem;font-family:inherit;box-sizing:border-box}
  input:focus{outline:none;border-color:#2563eb}
  button{margin-top:1rem;width:100%;padding:.65rem;background:#2563eb;color:#fff;border:none;border-radius:6px;font-size:.9rem;cursor:pointer;font-family:inherit}
  button:hover{background:#1d4ed8}
  .hint{font-size:.75rem;color:#777;margin-top:1rem;line-height:1.4}
</style>
</head>
<body>
<form class=wrap method=post action="/submit/${encodeURIComponent(token)}">
  <h1>Enter value</h1>
  <div class=sub>Secret name: <code>${escapeHtml(name)}</code></div>
  <input type=password name=value placeholder="secret value" autofocus required>
  <button type=submit>Save</button>
  <div class=hint>The value is sent over HTTPS, encrypted on the server (AES-256-GCM), and the link works only once.</div>
</form>
</body>
</html>`;
}

function escapeHtml(s: string): string {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/* ================================================================
   WEB UI
   ================================================================ */

const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SSS</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a0a;color:#e0e0e0;min-height:100vh}
.container{max-width:960px;margin:0 auto;padding:2rem}
h1{font-size:1.4rem;margin-bottom:1.5rem;display:flex;align-items:center;gap:.75rem}
h1 .dim{color:#555;font-size:.8rem;font-weight:400}
.login{display:flex;justify-content:center;align-items:center;min-height:100vh}
.login-card{background:#161616;border:1px solid #333;border-radius:12px;padding:2rem;width:100%;max-width:360px}
.login-card h1{justify-content:center;margin-bottom:1.5rem}
.fg{margin-bottom:.75rem}
.fg label{display:block;font-size:.75rem;color:#777;margin-bottom:.2rem;text-transform:uppercase;letter-spacing:.04em}
input,textarea{width:100%;padding:.55rem .7rem;border:1px solid #333;border-radius:6px;background:#1a1a1a;color:#e0e0e0;font-size:.875rem;font-family:inherit}
input:focus,textarea:focus{outline:none;border-color:#2563eb}
.btn{display:inline-flex;align-items:center;gap:.4rem;padding:.45rem .85rem;border:none;border-radius:6px;font-size:.8rem;cursor:pointer;font-family:inherit;text-decoration:none}
.btn-p{background:#2563eb;color:#fff}.btn-p:hover{background:#1d4ed8}
.btn-d{background:transparent;color:#ef4444;border:1px solid #5c2020}.btn-d:hover{background:#ef4444;color:#fff}
.btn-g{background:transparent;color:#888}.btn-g:hover{color:#ddd}
.btn-sm{padding:.3rem .6rem;font-size:.75rem}
table{width:100%;border-collapse:collapse;margin-top:1rem}
th{text-align:left;font-size:.7rem;color:#555;text-transform:uppercase;letter-spacing:.05em;padding:.65rem .5rem;border-bottom:1px solid #222}
td{padding:.6rem .5rem;border-bottom:1px solid #151515;font-size:.8rem;vertical-align:middle}
tr:hover td{background:#0f0f0f}
td a{color:#60a5fa;text-decoration:none}td a:hover{text-decoration:underline}
.add-panel{background:#111;border:1px solid #333;border-radius:8px;padding:1.2rem;margin-top:1rem;display:none}
.add-panel.open{display:block}
.empty{text-align:center;padding:3rem;color:#555}
.actions{display:flex;gap:.5rem}
.sep{width:1px;height:1rem;background:#333;margin:0 .25rem}
#logout{margin-left:auto}
.who{margin-left:auto;color:#666;font-size:.8rem}
.pend{color:#eab308;font-size:.7rem;border:1px solid #4a3a00;border-radius:4px;padding:0 .3rem;margin-left:.4rem}
</style>
</head>
<body>
<div id="app"></div>
<script id="sss-session" type="application/json">__SSS_SESSION__</script>
<script>
const TK='sss_tk';
const SESSION=JSON.parse(document.getElementById('sss-session').textContent||'{}');
const MODE=SESSION.mode==='sso'?'sso':'bearer';
const USER=SESSION.user||null;
const LOGIN_URL=SESSION.login_url||'';
const LOGOUT_URL=SESSION.logout_url||'';
function getToken(){
  const h=location.hash;
  if(h.startsWith('#token=')){const t=h.slice(7);sessionStorage.setItem(TK,t);history.replaceState(null,'',location.pathname);return t;}
  return sessionStorage.getItem(TK);
}
function esc(s){if(!s)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function signIn(){
  const url=LOGIN_URL+(LOGIN_URL.indexOf('?')>=0?'&':'?')+'rd='+encodeURIComponent(location.href);
  window.location.href=url;
}
async function api(path,opts={}){
  const headers={'Content-Type':'application/json',...(opts.headers||{})};
  if(MODE==='bearer'){
    const t=getToken();if(!t)throw new Error('no token');
    headers['Authorization']='Bearer '+t;
  }
  let r;
  try{
    r=await fetch(path,{...opts,headers,credentials:'same-origin'});
  }catch(e){
    /* A cross-origin redirect to the sign-in page is not readable by
       fetch — treat it as an expired session. */
    if(MODE==='sso'){signIn();throw new Error('sign-in required');}
    throw e;
  }
  if(MODE==='sso'&&r.redirected){window.location.href=r.url;throw new Error('redirected to sign-in');}
  if(r.status===401){
    if(MODE==='sso'){signIn();throw new Error('unauthorized');}
    sessionStorage.removeItem(TK);showLogin();throw new Error('unauthorized');
  }
  if(!r.ok){const e=await r.json().catch(()=>({error:r.statusText}));throw new Error(e.error||'err');}
  if(!(r.headers.get('content-type')||'').includes('application/json')){
    /* The proxy answered with the sign-in page instead of API JSON. */
    if(MODE==='sso'){signIn();throw new Error('sign-in required');}
    throw new Error('unexpected response');
  }
  return r.json();
}

function showLogin(){
  document.getElementById('app').innerHTML=
    '<div class="login"><div class="login-card"><h1>SSS</h1><p style="color:#777;font-size:.85rem;margin-bottom:1.2rem">Secret Storage</p>'+
    '<div class="fg"><label>Bearer Token</label><input id="tk" placeholder="paste token" autofocus></div>'+
    '<button class="btn btn-p" style="width:100%" onclick="doLogin()">Login</button></div></div>';
  document.getElementById('tk').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});
}
function doLogin(){
  const t=document.getElementById('tk').value.trim();if(!t)return;
  sessionStorage.setItem(TK,t);showDash();loadSecrets();
}
function logout(){sessionStorage.removeItem(TK);showLogin();}

function showDash(){
  const account=MODE==='sso'
    ? '<span class="who">'+esc(USER)+'</span><a class="btn btn-g btn-sm" id="signout" href="#" title="Ends your session on every bezrabotnyi.com site">Sign out everywhere</a>'
    : '<button class="btn btn-g btn-sm" id="logout">Logout</button>';
  document.getElementById('app').innerHTML=
    '<div class="container"><h1>SSS <span class="dim">Secret Storage</span> '+account+'</h1>'+
    '<div style="display:flex;gap:.5rem"><button class="btn btn-p" onclick="toggleAdd(true)">+ Add Secret</button></div>'+
    '<div class="add-panel" id="addp">'+
      '<div class="fg"><label>Name</label><input id="f-name" placeholder="e.g. yandex_password"></div>'+
      '<div class="fg"><label>Description</label><input id="f-desc" placeholder="optional"></div>'+
      '<div class="fg"><label>URL</label><input id="f-url" placeholder="e.g. https://passport.yandex.ru"></div>'+
      '<div class="fg"><label>Account</label><input id="f-acct" placeholder="e.g. user@yandex.ru"></div>'+
      '<div class="fg"><label>Value</label><input type="password" id="f-val" placeholder="secret value"></div>'+
      '<div style="display:flex;gap:.5rem;margin-top:.5rem"><button class="btn btn-p" onclick="doSave()">Save</button><button class="btn btn-g" onclick="toggleAdd(false)">Cancel</button></div>'+
    '</div>'+
    '<table><thead><tr><th>Name</th><th>Description</th><th>URL</th><th>Account</th><th style="width:90px">Created</th><th></th></tr></thead>'+
    '<tbody id="tbody"></tbody></table>'+
    '<div class="empty" id="empty" style="display:none">No secrets yet</div>'+
    '</div>';
  const lo=document.getElementById('logout');
  if(lo)lo.onclick=logout;
  const so=document.getElementById('signout');
  if(so)so.onclick=e=>{
    e.preventDefault();
    /* The shared auth cookie covers every *.bezrabotnyi.com site, so
       signing out here ends the session everywhere. */
    if(!confirm('Sign out of all bezrabotnyi.com sites?'))return;
    window.location.href=LOGOUT_URL+(LOGOUT_URL.indexOf('?')>=0?'&':'?')+'rd='+encodeURIComponent(location.href);
  };
}
function toggleAdd(open){
  const p=document.getElementById('addp');
  if(open){p.classList.add('open');document.getElementById('f-name').focus();}
  else{p.classList.remove('open');}
}
async function loadSecrets(){
  try{
    const d=await api('/api/secrets');
    const tbody=document.getElementById('tbody');
    const empty=document.getElementById('empty');
    if(!d.secrets.length){tbody.innerHTML='';empty.style.display='block';return;}
    empty.style.display='none';
    tbody.innerHTML=d.secrets.map(s=>'<tr>'+
      '<td><strong>'+esc(s.name)+'</strong>'+(s.meta&&s.meta.pending?'<span class="pend">pending</span>':'')+'</td>'+
      '<td>'+esc(s.meta?.description)+'</td>'+
      '<td>'+(s.meta?.url?'<a href="'+esc(s.meta.url)+'" target="_blank">'+esc(s.meta.url)+'</a>':'')+'</td>'+
      '<td>'+esc(s.meta?.account)+'</td>'+
      '<td style="color:#555;font-size:.75rem">'+new Date(s.meta.created).toLocaleDateString()+'</td>'+
      '<td class="actions"><button class="btn btn-g btn-sm" onclick="doRename(\''+esc(s.name)+'\')">Rename</button>'+
      '<button class="btn btn-d btn-sm" onclick="doDelete(\''+esc(s.name)+'\')">Del</button></td>'+
    '</tr>').join('');
  }catch(e){alert(e.message);}
}
async function doSave(){
  const name=document.getElementById('f-name').value.trim();
  const value=document.getElementById('f-val').value;
  if(!name){alert('Name is required');return;}
  if(!value){alert('Value is required');return;}
  try{
    await api('/api/secrets',{method:'POST',body:JSON.stringify({
      name,
      description:document.getElementById('f-desc').value.trim()||undefined,
      url:document.getElementById('f-url').value.trim()||undefined,
      account:document.getElementById('f-acct').value.trim()||undefined,
      value
    })});
    toggleAdd(false);
    ['f-name','f-desc','f-url','f-acct','f-val'].forEach(id=>document.getElementById(id).value='');
    loadSecrets();
  }catch(e){alert(e.message);}
}
async function doDelete(name){
  if(!confirm('Delete "'+name+'"?'))return;
  try{await api('/api/secrets/'+name,{method:'DELETE'});loadSecrets();}catch(e){alert(e.message);}
}
async function doRename(name){
  const next=prompt('New name for "'+name+'":',name);
  if(next===null)return;
  const clean=next.trim();
  if(!clean){alert('New name is required');return;}
  if(clean===name)return;
  try{
    await api('/api/secrets/'+encodeURIComponent(name)+'/rename',{method:'POST',body:JSON.stringify({name:clean})});
    loadSecrets();
  }catch(e){alert(e.message);}
}

/* init */
if(MODE==='sso'){showDash();loadSecrets();}
else{const t=getToken();if(t){showDash();loadSecrets();}else{showLogin();}}
</script>
</body>
</html>`;

function webUiHtml(session: { mode: SessionMode; user?: string }): string {
  const bootstrap = JSON.stringify({
    mode: session.mode,
    user: session.user ?? null,
    login_url: SSO_LOGIN_URL(),
    logout_url: SSO_LOGOUT_URL(),
  }).replace(/</g, '\\u003c');
  return HTML_TEMPLATE.replace('__SSS_SESSION__', () => bootstrap);
}

app.get('/', (req: Request, res: Response) => {
  res.set('Cache-Control', 'no-store');
  res.set('X-Content-Type-Options', 'nosniff');
  res.type('html').send(webUiHtml(sessionFor(req)));
});

/* ================================================================
   START
   ================================================================ */
app.listen(PORT, '127.0.0.1', () => {
  console.log(`SSS listening on 127.0.0.1:${PORT}`);
  console.log(`Web UI:  ${SERVER_URL}`);
  console.log(`MCP:      ${SERVER_URL}/mcp`);
  console.log(`API:      ${SERVER_URL}/api/secrets`);
});
