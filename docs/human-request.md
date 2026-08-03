# Human Request in the secret stack

Simple Secret Storage (SSS) is the internal secret store. The agent-facing name for the human-entry boundary is planned to be Ask Secret.

## Current code-backed behavior

SSS already does four useful things:

- Stores named secrets and exposes metadata-only listing.
- Returns a one-time user-input URL when a secret is missing or still pending, so a human can fill it in through the web UI.
- Supports encrypted delivery to a registered agent using an age/X25519 public key.
- Provides `sss-run`, which reads a secret from stdin and pipes it directly into a local consumer command without printing the plaintext.

Important current detail: if an agent does not provide a registered `agent_id`, SSS can fall back to base64 delivery. That is not end-to-end encrypted and should not be treated as the Ask Secret boundary for LLM-facing use.

## Non-goals

- SSS is not the general task runner or scheduler.
- SSS is not the agent router.
- SSS is not the notification system.
- SSS is not the session-resume system.
- SSS should not become a place where humans paste secrets into chat.

## Proposed Ask Secret boundary

Ask Secret should be the thin human-request layer on top of SSS:

1. An agent asks for a secret by name.
2. If the secret is missing or pending, Ask Secret returns a short-lived human entry link.
3. The human enters the value in the browser.
4. SSS stores the secret encrypted at rest.
5. When the agent asks again, SSS returns encrypted delivery for a registered agent or a safe non-LLM handoff artifact.

The boundary should stay narrow: Ask Secret coordinates the request; SSS stores and serves the secret; the agent side consumes only encrypted bytes or an opaque reference.

## How Ask Secret should interact with other services

- Notify: used to alert the human that a secret is waiting, or that a request needs attention.
- agent-resume: used to wake the paused task after the secret arrives.
- Agent Herder: used to route the request to the right agent/task and to keep ownership and delivery metadata aligned.

These integrations are proposed orchestration, not current SSS behavior.

## Safety invariant

Plaintext must never enter LLM context.

That means:

- no secret value in prompts, tool output, logs, or task notes;
- no copy/paste path from the human entry form back into chat;
- no fallback that exposes the raw value to the model when a safer encrypted path exists;
- only opaque references, encrypted blobs, or stdin handoff to a local consumer.

If a flow cannot preserve that invariant, it should fail closed.
