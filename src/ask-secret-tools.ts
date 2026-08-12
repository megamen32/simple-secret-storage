import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';


const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_SSS_RUN = resolve(HERE, '../bin/sss-run.mjs');
const DEFAULT_SSS_GET = resolve(HERE, '../bin/sss-get.mjs');

export type AskSecretOperations = {
  probeSecret(input: { name: string }): unknown | Promise<unknown>;
  runProfile(input: { name: string; profile: string }): unknown | Promise<unknown>;
};

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
    'Check whether a named secret is ready. The secret value is never returned to the AI and is not consumed by this check.',
    { name: z.string().min(1).describe('Provisioned secret name') },
    async ({ name }) => textResult(await operations.probeSecret({ name })),
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

export function createRuntimeOperations(): AskSecretOperations {
  return {
    async probeSecret({ name }) {
      await runOpaque(
        [process.env.SSS_GET_BIN || DEFAULT_SSS_GET, name],
        { SSS_REQUIRE_AGE: '1', SSS_PROBE_ONLY: '1' },
      );
      return { status: 'ready', name };
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
