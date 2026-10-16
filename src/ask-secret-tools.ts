import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';


const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_SSS_RUN = resolve(HERE, '../bin/sss-run.mjs');
const DEFAULT_SSS_GET = resolve(HERE, '../bin/sss-get.mjs');

export type AskSecretOperations = {
  probeSecret(input: { name: string; request_id?: string }): unknown | Promise<unknown>;
  runProfile(input: { name: string; profile: string }): unknown | Promise<unknown>;
};

// A missing label is never a reason to interrupt the human. A supplied request
// identity also makes retries of an unnamed handoff resolve the same form.
export function secretRequestName(name?: string, requestId?: string): string {
  return name?.trim() || `secret_${requestId || randomUUID()}`;
}

function textResult(result: unknown) {
  return {
    content: [{
      type: 'text' as const,
      text: typeof result === 'string' ? result : JSON.stringify(result),
    }],
  };
}

export function registerAskSecretTools(server: McpServer, operations: AskSecretOperations): void {
  server.tool(
    'ask_secret',
    'Open a one-time browser form for entering a secret, or return ready when already supplied. Omit name to generate one automatically; never ask the user for a name. Returns only status and an input URL, never the secret or a download URL.',
    {
      name: z.string().optional().describe('Optional label; generated automatically when omitted'),
      request_id: z.string().uuid().optional().describe('Reuse this optional request identity when retrying an unnamed form'),
    },
    async ({ name, request_id }) => textResult(await operations.probeSecret({ name: secretRequestName(name, request_id), ...(request_id ? {request_id} : {}) })),
  );
  server.tool(
    'ask_secret_run',
    'Run a preconfigured profile with the named secret on stdin. The secret is never returned to the AI, arguments, or environment.',
    {
      name: z.string().min(1).describe('Provisioned secret name'),
      profile: z.string().min(1).describe('Audited server-side stdin profile name'),
    },
    async ({ name, profile }) => textResult(await operations.runProfile({ name, profile })),
  );
}

function configuredProfiles(): Record<string, { executable: string; args?: string[] }> {
  let profiles: unknown;
  try {
    profiles = JSON.parse(process.env.ASK_SECRET_PROFILES_JSON || '{}');
  } catch {
    throw new Error('ASK_SECRET_PROFILES_JSON must be valid JSON');
  }
  if (!profiles || Array.isArray(profiles) || typeof profiles !== 'object') {
    throw new Error('ASK_SECRET_PROFILES_JSON must be an object');
  }
  return profiles as Record<string, { executable: string; args?: string[] }>;
}

function runOpaque(argv: string[], extraEnv: Record<string, string>): Promise<void> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, argv, {
      env: { ...process.env, ...extraEnv },
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    child.once('error', () => rejectRun(new Error('AskSecret runtime failed to start')));
    child.once('close', code => {
      if (code === 0) resolveRun();
      else rejectRun(new Error('AskSecret runtime failed'));
    });
  });
}

function requestOpaque(name: string, requestId?: string): Promise<unknown> {
  return new Promise((resolveRequest, rejectRequest) => {
    const child = spawn(process.execPath, [process.env.SSS_GET_BIN || DEFAULT_SSS_GET, name, ...(requestId ? [requestId] : [])], {
      env: { ...process.env, SSS_REQUEST_ONLY: '1' },
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const timer = setTimeout(() => child.kill(), 20_000);
    let output = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      output += chunk;
      if (output.length > 8192) child.kill();
    });
    child.once('error', () => { clearTimeout(timer); rejectRequest(new Error('AskSecret form request failed to start')); });
    child.once('close', code => {
      clearTimeout(timer);
      if (code !== 0 || output.length > 8192) return rejectRequest(new Error('AskSecret form request failed'));
      try {
        const result = JSON.parse(output);
        if (result.name !== name || !['ready', 'pending'].includes(result.status)) throw new Error();
        if (result.status === 'ready') return resolveRequest({status: 'ready', name});
        const url = new URL(result.input_url);
        if (!['http:', 'https:'].includes(url.protocol) || !/^\/i\/[A-Za-z0-9_-]+$/.test(url.pathname) || url.username || url.password || url.search || url.hash) throw new Error();
        resolveRequest({status: 'pending', name, input_url: url.href, request_id: result.request_id});
      } catch { rejectRequest(new Error('AskSecret returned an invalid form response')); }
    });
  });
}

export function createRuntimeOperations(): AskSecretOperations {
  return {
    async probeSecret({ name, request_id }) {
      return requestOpaque(name, request_id);
    },
    async runProfile({ name, profile }) {
      const selected = configuredProfiles()[profile];
      if (!selected || typeof selected.executable !== 'string') {
        throw new Error(`unknown AskSecret profile: ${profile}`);
      }
      const args = selected.args ?? [];
      if (!Array.isArray(args) || args.some(arg => typeof arg !== 'string')) {
        throw new Error(`invalid AskSecret profile: ${profile}`);
      }
      await runOpaque(
        [process.env.SSS_RUN_BIN || DEFAULT_SSS_RUN, name, '--', selected.executable, ...args],
        { SSS_REQUIRE_AGE: '1' },
      );
      return { status: 'completed', name, profile };
    },
  };
}
