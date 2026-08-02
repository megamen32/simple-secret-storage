import express, { Request, Response, NextFunction } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { randomBytes, randomUUID } from 'node:crypto';
import { Storage, SecretMeta } from './storage.js';
import { ensureDirs, BLOBS_DIR } from './config.js';

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

/* Order: app.all('/mcp') AFTER express.json() — stateless transport
   takes pre-parsed JSON body as parsedBody (no session, no stream). */
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

/* ---- Auth middleware ---- */
function auth(req: Request, res: Response, next: NextFunction): void {
  if (req.headers.authorization !== `Bearer ${API_KEY}`) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }
  next();
}

/* ================================================================
   MCP SERVER (Streamable HTTP)
   ================================================================ */
const mcp = new McpServer({ name: 'sss', version: '1.0.0' });
/* Note: tools are registered per-session in makeServer() below —
   re-registering on this shared instance would conflict with the
   stateful per-session transport model. Keep `mcp` as a placeholder
   so other code (e.g. session-end hooks) can be added later. */
void mcp;

/* ---- Mount MCP on Express ---- */
/* ---- Stateful MCP transport (per-session) ----
   The MCP SDK requires a fresh StreamableHTTPServerTransport per session in
   stateful mode. We keep a map sessionId -> transport so subsequent calls
   (tools/list, tools/call) reuse the same transport. A fresh McpServer is
   created per session and tools are registered on it. */
const transports: Record<string, StreamableHTTPServerTransport> = {};

function makeServer(): McpServer {
  const s = new McpServer({ name: 'sss', version: '1.0.0' });
  s.tool(
    'get_secret',
    'Get a secret by name. If found, returns the path to an AES-encrypted blob file ' +
      'on disk plus a one-time URL to fetch it. The LLM must pipe the file contents ' +
      'into its target command — NEVER read or display the file (it is opaque bytes). ' +
      'If not found, tells the agent to ask the user to create it via the web UI.',
    { name: z.string().describe('Secret name'),
      agent_id: z.string().optional().describe('Agent ID registered via register_agent. If provided, the value is encrypted with the agent\'s age public key (true E2E); otherwise it is returned as base64 (SSS sees the plaintext).') },
    async ({ name, agent_id }) => {
      const meta = storage.getSecretMeta(name);
      // Pending = user hasn't entered the value yet. Surface the
      // user-input URL so the agent forwards it again.
      if (!meta || meta.pending) {
        const { token, fresh } = storage.requestPending(name);
        return {
          content: [{
            type: 'text' as const,
            text:
              (meta?.pending
                ? `Secret "${name}" is pending user input.\n`
                : `Secret "${name}" not found.\n`) +
              `${fresh ? 'Send the user this one-time URL' : 'Re-send the same one-time URL'} to enter the value:\n` +
              `  ${SERVER_URL}/i/${token}\n\n` +
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
  return s;
}

app.all('/mcp', async (req: any, res: any, next: NextFunction) => {
  if (req.headers.authorization !== `Bearer ${API_KEY}`) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }
  try {
    const sessionId =
      (req.headers['mcp-session-id'] as string | undefined) ?? undefined;
    let transport: StreamableHTTPServerTransport;
    if (sessionId && transports[sessionId]) {
      transport = transports[sessionId];
    } else if (!sessionId && isInitializeRequest(req.body)) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid: string) => {
          transports[sid] = transport;
        },
      });
      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid) delete transports[sid];
      };
      await makeServer().connect(transport);
    } else {
      res.status(400).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Bad Request: no valid session ID provided' },
        id: null,
      });
      return;
    }
    await transport.handleRequest(req, res, req.body);
  } catch (e: any) {
    console.error('[mcp] error:', e?.message ?? e, e?.stack);
    if (!res.headersSent) res.status(500).json({ error: e?.message ?? 'internal error' });
  }
});

/* ================================================================
   REST API  (/api/*)
   ================================================================ */

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
  res.type('html').send(
    '<!doctype html><meta charset=utf-8><title>SSS</title>' +
    '<body style="font-family:sans-serif;max-width:480px;margin:4rem auto;color:#444">' +
    '<h2>Saved</h2><p>Value for <code>' + filled + '</code> has been stored encrypted. ' +
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

const HTML = `<!DOCTYPE html>
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
.btn{display:inline-flex;align-items:center;gap:.4rem;padding:.45rem .85rem;border:none;border-radius:6px;font-size:.8rem;cursor:pointer;font-family:inherit}
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
</style>
</head>
<body>
<div id="app"></div>
<script>
const TK='sss_tk';
function getToken(){
  const h=location.hash;
  if(h.startsWith('#token=')){const t=h.slice(7);sessionStorage.setItem(TK,t);history.replaceState(null,'',location.pathname);return t;}
  return sessionStorage.getItem(TK);
}
function esc(s){if(!s)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
async function api(path,opts={}){
  const t=getToken();if(!t)throw new Error('no token');
  const r=await fetch(path,{...opts,headers:{'Authorization':'Bearer '+t,'Content-Type':'application/json',...opts.headers}});
  if(r.status===401){sessionStorage.removeItem(TK);showLogin();throw new Error('unauthorized');}
  if(!r.ok){const e=await r.json().catch(()=>({error:r.statusText}));throw new Error(e.error||'err');}
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
  document.getElementById('app').innerHTML=
    '<div class="container"><h1>SSS <span class="dim">Secret Storage</span> <button class="btn btn-g btn-sm" id="logout">Logout</button></h1>'+
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
  document.getElementById('logout').onclick=logout;
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
      '<td><strong>'+esc(s.name)+'</strong></td>'+
      '<td>'+esc(s.meta?.description)+'</td>'+
      '<td>'+(s.meta?.url?'<a href="'+esc(s.meta.url)+'" target="_blank">'+esc(s.meta.url)+'</a>':'')+'</td>'+
      '<td>'+esc(s.meta?.account)+'</td>'+
      '<td style="color:#555;font-size:.75rem">'+new Date(s.meta.created).toLocaleDateString()+'</td>'+
      '<td class="actions"><button class="btn btn-d btn-sm" onclick="doDelete(\''+esc(s.name)+'\')">Del</button></td>'+
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

/* init */
const t=getToken();
if(t){showDash();loadSecrets();}else{showLogin();}
</script>
</body>
</html>`;

app.get('/', (_req: Request, res: Response) => {
  res.type('html').send(HTML);
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
