/**
 * The only SSS completion integration. The URL is deliberately a constant:
 * operators can enable the named integration, but cannot configure an
 * arbitrary destination from the browser request or request metadata.
 */
export const ALLOWED_COMPLETION_CALLBACK =
  'http://127.0.0.1:8780/internal/human-requests/sss-completion';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function getCompletionCallback(env: NodeJS.ProcessEnv = process.env): string | null {
  const selection = env.SSS_HUMAN_REQUEST_CALLBACK;
  if (!selection) return null;
  if (selection !== 'agent-herder') {
    throw new Error('unsupported callback configuration');
  }
  return ALLOWED_COMPLETION_CALLBACK;
}

export interface CompletionEvent {
  event: 'sss.secret_input.completed';
  event_version: 1;
  request_id: string;
  status: 'completed';
  result_ref: string;
}

export function buildCompletionEvent(requestId: string, resultRef: string): CompletionEvent {
  if (!UUID.test(requestId) || !UUID.test(resultRef)) {
    throw new Error('completion metadata must be UUIDs');
  }
  return {
    event: 'sss.secret_input.completed',
    event_version: 1,
    request_id: requestId,
    status: 'completed',
    result_ref: resultRef,
  };
}

/** Best-effort delivery: SSS has already stored the encrypted value. */
export async function postCompletion(
  url: string,
  event: CompletionEvent,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  if (url !== ALLOWED_COMPLETION_CALLBACK) {
    throw new Error('completion callback URL is not allowlisted');
  }
  try {
    await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(2_000),
    });
  } catch {
    // Callback delivery must never turn a successful secret submission into
    // an error or cause the browser to retry the one-time submission.
  }
}
