# SSS — Simple Secret Storage (MCP)

End-to-end encrypted secret delivery for LLM agents.

The agent asks for a secret **by name**. The server returns a one-time URL
to an **age-encrypted blob** (X25519). Only the agent's private key can
decrypt it. The server never sees the plaintext in the wire response.

## Why

When an LLM agent needs a password / API key / token, the worst thing is
to have the secret appear in the MCP tool response — it ends up in the
model context, the chat history, and any logs that record tool outputs.

SSS solves this by:

1. **Server stores the secret encrypted** (AES-256-GCM, master key in
   `~/.sss/key`, mode 0600).
2. **Agent registers an age (X25519) public key** via MCP `register_agent`.
3. **`get_secret(name, agent_id)` returns a one-time fetch URL**. The
   fetch responds with **armored age ciphertext** for that agent's public
   key.
4. **Agent decrypts locally with its private key** and pipes the
   plaintext into the target command. Plaintext exists only in the
   command's stdin.

The server **never** has the agent's private key, so even if the server
is compromised, the attacker only gets ciphertext they can't decrypt.

If the agent doesn't register (no `agent_id` parameter), `get_secret`
falls back to base64 for convenience — but the server **does** see the
plaintext at fetch time. Use `agent_id` for any non-trivial secret.

## Quick start

### 1. Server: build, install, systemd

```bash
cd ~/agents-projects/simple-secret-storage
npm ci                          # installs production deps
npm run build                   # dev deps included for tsc
sudo install -m 0644 systemd/sss.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sss
```

Generate a strong bearer token once:

```bash
echo "SSS_API_KEY=$(openssl rand -hex 32)" \
  > ~/.config/sss-mcp/api-key.env
chmod 600 ~/.config/sss-mcp/api-key.env
```

The systemd unit reads this file via `EnvironmentFile=`.

### 2. nginx: terminate TLS, proxy to SSS

`nginx/pswd.bezrabotnyi.com.conf` ships in the repo. Adapt paths and
hostnames; symlink into `sites-enabled`, then:

```bash
sudo certbot certonly --nginx -d pswd.bezrabotnyi.com \
  --non-interactive --agree-tos --register-unsafely-without-email
sudo nginx -t && sudo systemctl reload nginx
```

The config has `access_log off` for `/i/`, `/submit/`, and `/d/`
locations — the URLs themselves are the credentials.

### 3. CLI wrapper for agents

`bin/sss-get.mjs` ships in the repo and provides a one-shot tool:

```bash
ln -sf "$(pwd)/bin/sss-get.mjs" ~/.local/bin/sss-get
```

First run creates `~/.config/sss-mcp/agent-identity.json` (mode 0600)
with a fresh X25519 identity and registers the public key with the
server.

Usage:

```bash
SSS_API_KEY=... sss-get yandex_password | <your-command>
```

or, with the env file in place:

```bash
sss-get yandex_password | <your-command>
```

`sss-get` will:

- generate the agent identity if missing,
- call MCP `register_agent`,
- call MCP `get_secret(name, agent_id)`,
- fetch `/d/<token>` and decrypt the age ciphertext locally,
- write plaintext to stdout.

### 4. Codex CLI

Already done in `~/.codex/config.toml`:

```toml
[mcp_servers.sss]
url = "https://pswd.bezrabotnyi.com/mcp"
bearer_token_env_var = "SSS_API_KEY"
```

`SSS_API_KEY` is loaded by `~/.profile` from `~/.config/sss-mcp/api-key.env`.

Restart Codex (`codex` in a new login shell). The agent will see four MCP
tools: `get_secret`, `list_secrets`, `delete_secret`, `register_agent`.

For tool calls, pass `agent_id` to `get_secret` to get true E2E.

### 5. Claude Code / Cursor / other MCP clients

```bash
claude mcp add sss --transport http \
  --url https://pswd.bezrabotnyi.com/mcp \
  --header "Authorization: Bearer ***"
```

## MCP tools

| Tool             | Parameters                                                | What it returns                                                                                                                  |
| ---------------- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `register_agent` | `agent_id`, `public_key` (age1...), `label?`              | Confirmation. Persists the public key in `~/.sss/agents.json`.                                                                   |
| `get_secret`     | `name`, `agent_id?`                                       | If pending → returns `/i/<token>` URL for the user to submit the value. If ready → returns `/d/<token>` URL (age if `agent_id`, else base64) with pipe-usage hint. |
| `list_secrets`   | —                                                         | Names + metadata (no values).                                                                                                    |
| `delete_secret`  | `name`                                                    | Confirmation.                                                                                                                    |

## Web UI for the user

The user opens the link from `get_secret`'s `not_found` /
`pending_user_input` response. URL pattern:

```
https://pswd.bezrabotnyi.com/i/<token>
```

A simple password input form. POST goes to `/submit/<token>`, value is
encrypted and stored. The link works once and expires.

## Architecture

```
User ─browser─→ nginx (pswd.bezrabotnyi.com, TLS, access_log off for /i/, /d/, /submit/)
                       └─127.0.0.1:8743─→ SSS (systemd, single Node process)
                                              ├─ /api/secrets   (Bearer, list/save/delete)
                                              ├─ /i/<token>     (anonymous form)
                                              ├─ /submit/<token>(anonymous POST)
                                              ├─ /d/<token>     (one-time, age-cipher OR base64)
                                              └─ /mcp           (Streamable HTTP, Bearer)
                                                            ↕ JSON-RPC
LLM Agent ─MCP──→ same SSS ─MCP─→ register_agent, get_secret, list_secrets, delete_secret
LLM Agent ─CLI──→ sss-get ────────→ same flows; decrypts locally with age identity
```

Files:

```
~/agents-projects/simple-secret-storage/
├── src/
│   ├── server.ts        # Express app + MCP tools + /i/, /submit/, /d/, /api/
│   ├── storage.ts       # ~/.sss/{key, secrets.json, blobs/, agents.json}
│   └── crypto.ts        # AES-256-GCM (storage) + age-encryption (wire)
├── bin/sss-get.mjs      # CLI wrapper for non-MCP shells
├── systemd/sss.service  # Single-process systemd unit
├── nginx/pswd.bezrabotnyi.com.conf
└── dist/                # tsc output
```

## Threat model

### Protected

- **Plaintext in MCP response / logs** — server returns URL + ciphertext only.
- **Plaintext on disk** — AES-256-GCM, master key at `~/.sss/key` (0600).
- **Plaintext in nginx access logs** — `/i/`, `/submit/`, `/d/` have `access_log off`.
- **Server compromise with `agent_id` mode** — attacker gets ciphertexts only, no agent private keys.
- **Network MITM** — TLS via Let's Encrypt; the nginx config uses the same `ssl_certificate_*` files as other `*.bezrabotnyi.com` sites.

### NOT protected

- **Plaintext at the command-STDIN destination.** If the receiving command
  writes its stdin to a file or logs it, the secret ends up there.
  `sss-get yandex_password | <cmd>` keeps the secret in the kernel pipe
  buffer only. There is no way around this — the secret has to reach the
  command somehow.
- **Plaintext in argv** — don't `cat /d/... | age --decrypt | xargs cmd $secret`.
  Use stdin redirection or `--password-file`.
- **Master key theft** — `~/.sss/key` is `0600` but unencrypted. If an
  attacker reads it, they can decrypt all stored blobs.
- **Compromise of the user's browser at the `/i/<token>` URL** — the
  one-time token has 256 bits of entropy; capture-and-replay within the
  5-minute window can submit an attacker-chosen value.
- **Loss of agent identity** — `~/.config/sss-mcp/agent-identity.json` is
  the only thing that lets the agent decrypt. Back it up encrypted or
  treat it as a one-shot device credential.

## Files created at runtime

```
~/.sss/key             32-byte AES key (mode 0600)
~/.sss/secrets.json    { name: { sha256, created, pending?, ... } } (mode 0600)
~/.sss/blobs/<name>.enc  AES-encrypted secret blob (mode 0600)
~/.sss/agents.json     { agent_id: { publicKey, ... } } (mode 0600)
~/.config/sss-mcp/api-key.env            SSS_API_KEY=... (mode 0600)
~/.config/sss-mcp/agent-identity.json    age identity (mode 0600)
```

## Operational notes

- `npm run build` requires `typescript` and `@types/*` (dev deps). On the
  production server, run `npm ci` (full install) before `npm run build`,
  not `npm ci --omit=dev`.
- The systemd unit must use `/usr/local/bin/node` (v22+). `/usr/bin/node`
  on this host is v12 and will fail to parse `??` and other ES2020+
  syntax.
- The agent identity is per-machine. If you move Codex to a new host,
  delete `~/.config/sss-mcp/agent-identity.json` and let it regenerate;
  the new public key will register automatically on the next `sss-get`
  call.
- The HTTP fetch URL (`/d/<token>`) is single-use (token deleted on first
  GET) and expires after 5 minutes. There is no refresh — if you missed
  it, call `get_secret` again to get a new URL.

## Manual lifecycle

```bash
sudo systemctl status sss            # running?
sudo systemctl restart sss           # after code changes
sudo journalctl -u sss -f            # live logs
sudo systemctl disable --now sss     # shut down
```

## Build for a fresh host

```bash
git clone <repo> ~/agents-projects/simple-secret-storage
cd ~/agents-projects/simple-secret-storage
npm ci
npm run build
sudo install -m 0644 systemd/sss.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sss
ln -sf "$(pwd)/bin/sss-get.mjs" ~/.local/bin/sss-get
```

Generate a fresh API key on the new host:

```bash
echo "SSS_API_KEY=$(openssl rand -hex 32)" > ~/.config/sss-mcp/api-key.env
chmod 600 ~/.config/sss-mcp/api-key.env
sudo systemctl restart sss
```