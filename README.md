# SSS — Simple Secret Storage (MCP)

End-to-end encrypted secret delivery for LLM agents.

The agent asks for a secret **by name**. The server returns a one-time URL
to an **age-encrypted blob** (X25519). Only the agent's private key can
decrypt it. The server never sees the plaintext in the wire response.

## Request a form

Call `ask_secret({})`: one call returns a browser input link and an automatic
random name. An optional `name` reuses a named handoff; an optional UUID
`request_id` keeps unnamed retries on the same form. Never ask the human to
invent a name. The form tool returns `pending` with `input_url`, or `ready`,
and never retrieves a secret or a download URL. After the user submits, use
only the separately authorized stdin consumer. `get_secret` also accepts an
omitted name for older clients.

**Always show a pending form link in a normal assistant message.** Many
harnesses hide MCP tool results from the user. Do not assume that returning
`input_url` from the MCP call displayed it. Reply with the exact returned URL
as a clickable Markdown link, for example: `Введите секрет в
[защищённой форме](URL)`, replacing `URL` with the exact returned
`input_url`. Never invent or alter the URL.

HTTP MCP uses the official SDK's stateless JSON transport. Pending forms and
encrypted secrets stay in storage across restarts; stale MCP session headers
do not block the next call. The stdio entrypoint uses the same tool definitions.

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

### 3. CLI wrappers for agents

Two scripts ship in `bin/`. Pick based on the threat model:

| Script      | Plaintext appears in…         | When to use                                               |
| ----------- | ------------------------------ | --------------------------------------------------------- |
| `sss-get`   | our `stdout` (then into pipe) | interactive use, `sss-get <name> \| xxd`, scripts you own |
| `sss-run`   | only the consumer's `stdin`   | handing a secret to an external command you don't trust with your stdout/argv/env |

Install both:

```bash
ln -sf "$(pwd)/bin/sss-get.mjs" ~/.local/bin/sss-get
ln -sf "$(pwd)/bin/sss-run.mjs" ~/.local/bin/sss-run
```

#### `sss-get <name>` — fetch + print to our stdout

```bash
sss-get yandex_password              # → plaintext on stdout
sss-get yandex_password | <your-command>
```

First run creates `~/.config/sss-mcp/agent-identity.json` (mode 0600)
with a fresh X25519 identity and registers the public key with the
server. Subsequent runs reuse it.

#### `sss-run <name> -- <consumer> [args...]` — pipe straight to a child

```bash
sss-run yandex_password -- curl -u : https://passport.yandex.ru/
sss-run api_token -- ssh -i ~/.ssh/id_ed25519 user@host 'echo ok'
```

The decrypted value is fed **only** to the consumer's stdin. It never
appears in our process's stdout, argv, or environment, and there is no
intermediate file on disk. The CLI itself enforces the `--` separator
so there's no chance of accidentally treating the consumer as an
option.
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

Restart Codex (`codex` in a new login shell). The remote SSS endpoint exposes
`ask_secret`, `list_secret_run_profiles`, `ask_secret_run`, `get_secret`,
`list_secrets`, `register_agent`, `delete_secret`, and `rename_secret`. The
narrow stdio entrypoint exposes `ask_secret`, `list_secret_run_profiles`, and
`ask_secret_run`.

For tool calls, pass `agent_id` to `get_secret` to get true E2E.

### 5. Claude Code / Cursor / other MCP clients

```bash
claude mcp add sss --transport http \
  --url https://pswd.bezrabotnyi.com/mcp \
  --header "Authorization: Bearer ***"
```

## How agents get the API key

Provision an SSS API key only to a machine whose operator is authorized for
full vault access, using a private, approved channel. The machine running
`sss-get` or `sss-run` needs the key; SSS does not register or classify hosts.
Anyone holding an SSS Bearer key can list, read,
save and delete every secret, so treat it as full vault access. Never put a
live key in this README, chat, shell history, or a command-line argument.

Create the client-side file, then populate it from a trusted secret-delivery
channel without putting the key in shell history or a command argument:

```bash
mkdir -p ~/.config/sss-mcp
umask 077
install -m 600 /dev/null ~/.config/sss-mcp/api-key.env
# Use a trusted editor or secret-provisioning tool to set SSS_API_KEY in this file.
chmod 600 ~/.config/sss-mcp/api-key.env
```

`sss-get` and `sss-run` read this file automatically. The systemd unit on the
server reads the same path on that host.

## MCP tools

The MCP server identifies itself as `simple-secret-storage`. Existing client
configuration aliases such as `AskSecret` remain valid; all harnesses use the
same SSS backend.

| Tool             | Parameters                                                | What it returns                                                                                                                  |
| ---------------- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `ask_secret` | `name?`, `request_id?` | `pending` with a one-time browser input URL, or `ready`; never a secret value or download URL. |
| `list_secret_run_profiles` | — | Configured consumer profile names only; never executable paths or arguments. |
| `ask_secret_run` | `name`, `profile` | Runs an exact configured profile with the secret on stdin; no value in the result, arguments or environment. |
| `register_agent` | `agent_id`, `public_key` (age1...), `label?`              | Confirmation. Persists the public key in `~/.sss/agents.json`.                                                                   |
| `get_secret`     | `name`, `agent_id?`                                       | If pending → returns `/i/<token>` URL for the user to submit the value. If ready → returns `/d/<token>` URL (age if `agent_id`, else base64) with pipe-usage hint. |
| `list_secrets`   | —                                                         | Names + metadata (no values).                                                                                                    |
| `delete_secret`  | `name`                                                    | Confirmation.                                                                                                                    |
| `rename_secret` | `name`, `new_name` | Renames the stored entry without reading or returning its value. |

Call `list_secret_run_profiles` before `ask_secret_run`. A profile is a
preconfigured server-side consumer; do not guess a name or pass arbitrary
commands through MCP. If no suitable profile exists, continue in the shell
where the current task runs: check `hostname -f` and `command -v sss-run`, then
run `sss-run <name> -- <fixed-consumer>`. The user does not need to classify
the machine. If the consumer must run on another server, use `ssh` itself as
the stdin consumer: `sss-run <name> -- ssh server-alias <fixed-remote-command>`.
The secret reaches the consumer only through stdin. Never use shell expansion,
command substitution, environment variables, or arguments to move the value.
The `/d/` retrieval grant is single-use and expires after five minutes; no
temporary profile is needed for a one-off operation.

## Manage long-lived secrets

Open `https://pswd.bezrabotnyi.com/` to manage named secrets. The page and its
browser management API use the existing `auth.bezrabotnyi.com` cookie SSO.
The page lists metadata and supports adding, renaming and deleting entries.
Use **Show** on a ready entry to explicitly reveal its value; **Hide** clears it
from the page, and refreshing the list clears all revealed values. Pending entries
cannot be revealed. The value endpoint is authenticated and returns `no-store`
responses. The `/mcp` endpoint keeps its Bearer-token authentication for agent
clients.

This SSO gate is limited to the management page and `/api/` browser requests.
The anonymous `/secret` upload and one-time `/i/<token>` input links remain
available under their existing contracts. A link token grants one pending
submission; the management list does not expose it.

## Web UI for the user

The user opens the link from `get_secret`'s `not_found` /
`pending_user_input` response. URL pattern:

```
https://pswd.bezrabotnyi.com/i/<token>
```

A simple password input form. POST goes to `/submit/<token>`, value is
encrypted and stored. The link works once and expires.

For a passwordless, anonymous upload that is not tied to a pending request,
open `https://pswd.bezrabotnyi.com/secret`. The page accepts only the secret
value, stores it encrypted under a generated UUID, and returns that opaque ID.

## Architecture

```
User ─browser─→ nginx (pswd.bezrabotnyi.com, TLS, access_log off for /i/, /d/, /submit/)
                       └─127.0.0.1:8743─→ SSS (systemd, single Node process)
                                              ├─ /api/secrets   (SSO browser or Bearer, list/save/rename/delete)
                                              ├─ /secret       (anonymous create, returns ID)
                                              ├─ /i/<token>     (anonymous form)
                                              ├─ /submit/<token>(anonymous POST)
                                              ├─ /d/<token>     (one-time, age-cipher OR base64)
                                              └─ /mcp           (Streamable HTTP, Bearer)
                                                            ↕ JSON-RPC
LLM Agent ─MCP──→ same SSS ─MCP─→ ask_secret, ask_secret_run, get_secret, list_secrets, register_agent, rename_secret, delete_secret
LLM Agent ─CLI──→ sss-get / sss-run ──→ same flows; decrypts locally with age identity
```

Files:

```
~/agents-projects/simple-secret-storage/
├── src/
│   ├── server.ts        # Express app + MCP tools + /i/, /submit/, /d/, /api/
│   ├── storage.ts       # ~/.sss/{key, secrets.json, blobs/, agents.json}
│   └── crypto.ts        # AES-256-GCM (storage) + age-encryption (wire)
├── bin/sss-install.mjs   # npx entrypoint → bash install.sh
├── bin/sss-get.mjs       # CLI: fetch and print to stdout
├── bin/sss-run.mjs       # CLI: pipe directly to a child process's stdin
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
  `sss-run <name> -- <cmd>` keeps the secret in the kernel pipe buffer
  only — there is no intermediate file, no stdout copy in the parent
  process, and the consumer's argv/env never see it. There is no way
  around this in principle — the secret has to reach the command
  somehow.
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
  or `sss-run` call.
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
ln -sf "$(pwd)/bin/sss-run.mjs" ~/.local/bin/sss-run
```

Generate a fresh API key on the new host:

```bash
echo "SSS_API_KEY=$(openssl rand -hex 32)" > ~/.config/sss-mcp/api-key.env
chmod 600 ~/.config/sss-mcp/api-key.env
sudo systemctl restart sss
```
