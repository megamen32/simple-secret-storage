# Graph Report - simple-secret-storage  (2026-10-23)

## Corpus Check
- 37 files · ~31,131 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 12 file(s) not represented in the graph (top: .lock 8, .service 2, (none) 1)

## Summary
- 258 nodes · 482 edges · 14 communities (10 shown, 4 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 6 edges (avg confidence: 0.83)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `3706c408`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- SSS — Simple Secret Storage (MCP)
- storage.ts
- package.json
- ask-secret-tools.ts
- compilerOptions
- server.ts
- ref_node_fs
- sss-get-identity.test.mjs
- install.sh
- Simple Secret Storage real-user canary access
- SSS non-goals (not a task runner, router, etc.)
- Форма секрета с первого вызова

## God Nodes (most connected - your core abstractions)
1. `Storage` - 20 edges
2. `sanitizeName()` - 14 edges
3. `readJson()` - 14 edges
4. `SECRETS_FILE()` - 13 edges
5. `BLOBS_DIR()` - 12 edges
6. `compilerOptions` - 10 edges
7. `SSS — Simple Secret Storage (MCP)` - 9 edges
8. `@modelcontextprotocol/sdk` - 8 edges
9. `ensureDirs()` - 8 edges
10. `makeServer()` - 8 edges

## Surprising Connections (you probably didn't know these)
- `Base64 fallback when agent_id is absent (not E2E)` --references--> `MCP tool: get_secret`  [EXTRACTED]
  docs/human-request.md → README.md
- `Safety invariant: plaintext never in LLM context` --references--> `age (X25519) end-to-end encryption`  [INFERRED]
  docs/human-request.md → README.md
- `Safety invariant: plaintext never in LLM context` --references--> `CLI: sss-run (pipe to child stdin)`  [INFERRED]
  docs/human-request.md → README.md
- `Human Request in the secret stack` --references--> `SSS — Simple Secret Storage (MCP)`  [EXTRACTED]
  docs/human-request.md → README.md
- `loadIdentity()` --calls--> `loadExistingAgentIdentity()`  [EXTRACTED]
  bin/sss-get.mjs → src/agent-identity.mjs

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Ask Secret boundary over SSS** — docs_ask_secret, readme_web_input_form, readme_get_secret, readme_sss_overview, docs_safety_invariant [EXTRACTED 0.90]
- **Proposed Ask Secret orchestration services** — docs_ask_secret, docs_notify, docs_agent_resume, docs_agent_herder [EXTRACTED 0.90]
- **End-to-end encrypted secret delivery path** — readme_get_secret, readme_register_agent, readme_age_x25519, readme_one_time_url, readme_agent_identity, readme_sss_get_cli, readme_sss_run_cli [EXTRACTED 0.95]

## Communities (14 total, 4 thin omitted)

### Community 0 - "SSS — Simple Secret Storage (MCP)"
Cohesion: 0.13
Nodes (26): Agent Herder (proposed integration), agent-resume (proposed integration), Ask Secret (proposed human-entry layer over SSS), Base64 fallback when agent_id is absent (not E2E), Human Request in the secret stack, Notify service (proposed integration), Safety invariant: plaintext never in LLM context, AES-256-GCM at-rest encryption (+18 more)

### Community 1 - "storage.ts"
Cohesion: 0.13
Nodes (22): age-encryption, BLOBS_DIR(), ensureDirs(), KEY_FILE(), sanitizeName(), SECRETS_FILE(), SSS_DIR(), writeKey() (+14 more)

### Community 2 - "package.json"
Cohesion: 0.07
Nodes (29): bin, ask-secret-mcp, ask-secret-run, sss-install, sss-run, dependencies, age-encryption, express (+21 more)

### Community 3 - "ask-secret-tools.ts"
Cohesion: 0.17
Nodes (11): AskSecretOperations, createRuntimeOperations(), DEFAULT_SSS_GET, DEFAULT_SSS_RUN, HERE, registerAskSecretTools(), secretRequestName(), textResult() (+3 more)

### Community 4 - "compilerOptions"
Cohesion: 0.17
Nodes (11): compilerOptions, declaration, esModuleInterop, module, moduleResolution, outDir, rootDir, skipLibCheck (+3 more)

### Community 5 - "server.ts"
Cohesion: 0.09
Nodes (28): ALLOWED_COMPLETION_CALLBACK, buildCompletionEvent(), CompletionEvent, getCompletionCallback(), postCompletion(), readKey(), sanitizeIdentity(), SSO_LOGIN_URL() (+20 more)

### Community 6 - "ref_node_fs"
Cohesion: 0.09
Nodes (12): HERE, INSTALL_SH, result, consumerWrite(), exitCode(), GETTER, HERE, main() (+4 more)

### Community 7 - "sss-get-identity.test.mjs"
Cohesion: 0.11
Nodes (17): callJson, ensureIdentity(), ensureRegistered(), IDENTITY_DIR, IDENTITY_PATH, loadIdentity(), mcp(), parseSse() (+9 more)

### Community 9 - "install.sh"
Cohesion: 0.70
Nodes (4): die(), say(), install.sh script, warn()

### Community 10 - "Simple Secret Storage real-user canary access"
Cohesion: 0.33
Nodes (5): Access limitations, Allowed scenario and cleanup, Authorized target and identity, Protected credential reference, Simple Secret Storage real-user canary access

## Knowledge Gaps
- **74 isolated node(s):** `IDENTITY_DIR`, `IDENTITY_PATH`, `callJson`, `HERE`, `INSTALL_SH` (+69 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 110 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `@modelcontextprotocol/sdk` connect `ref_node_fs` to `package.json`, `ask-secret-tools.ts`, `server.ts`?**
  _High betweenness centrality (0.096) - this node is a cross-community bridge._
- **Why does `Storage` connect `storage.ts` to `server.ts`?**
  _High betweenness centrality (0.040) - this node is a cross-community bridge._
- **Why does `zod` connect `package.json` to `ask-secret-tools.ts`, `server.ts`?**
  _High betweenness centrality (0.029) - this node is a cross-community bridge._
- **What connects `IDENTITY_DIR`, `IDENTITY_PATH`, `callJson` to the rest of the system?**
  _74 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `SSS — Simple Secret Storage (MCP)` be split into smaller, more focused modules?**
  _Cohesion score 0.12923076923076923 - nodes in this community are weakly interconnected._
- **Should `storage.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.13107822410147993 - nodes in this community are weakly interconnected._
- **Should `package.json` be split into smaller, more focused modules?**
  _Cohesion score 0.06666666666666667 - nodes in this community are weakly interconnected._