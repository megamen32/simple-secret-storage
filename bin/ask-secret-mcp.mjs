#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const SELF = fileURLToPath(import.meta.url);
const DEFAULT_SSS_RUN = resolve(dirname(SELF), 'sss-run.mjs');
const DEFAULT_SSS_GET = resolve(dirname(SELF), 'sss-get.mjs');

/**
 * Convert an adapter result into an MCP text response.
 *
 * @param {unknown} result Opaque status returned by the trusted adapter.
 * @returns {{content: Array<{type: 'text', text: string}>}} MCP response.
 */
function textResult(result) {
  return {
    content: [{
      type: 'text',
      text: typeof result === 'string' ? result : JSON.stringify(result),
    }],
  };
}

/**
 * Create the narrow agent-facing AskSecret MCP surface.
 *
 * The caller supplies runtime-bound operations. This surface deliberately has
 * no identity-management, enumeration, deletion, or plaintext-return tools.
 *
 * @param {{
 *   probeSecret: (input: {name: string}) => unknown | Promise<unknown>,
 *   runProfile: (input: {name: string, profile: string}) => unknown | Promise<unknown>,
 * }} operations Trusted runtime-bound operations.
 * @returns {McpServer} An unconnected MCP server exposing two narrow tools.
 * @throws {TypeError} If either required operation is missing.
 */
export function createAskSecretServer({ probeSecret, runProfile }) {
  if (typeof probeSecret !== 'function' || typeof runProfile !== 'function') {
    throw new TypeError('AskSecret requires probeSecret and runProfile operations');
  }

  const server = new McpServer({ name: 'ask-secret', version: '1.0.0' });
  server.tool(
    'ask_secret',
    'Check whether a named secret is ready for this runtime identity. The secret is never returned to the AI and the one-use payload is not consumed.',
    { name: z.string().min(1).describe('Provisioned secret name') },
    async ({ name }) => textResult(await probeSecret({ name })),
  );
  server.tool(
    'ask_secret_run',
    'Run a preconfigured stdin-only profile with a named secret. Plaintext is sent only to that process stdin, never to the AI, arguments, or environment.',
    {
      name: z.string().min(1).describe('Provisioned secret name'),
      profile: z.string().min(1).describe('Audited stdin profile name'),
    },
    async ({ name, profile }) => textResult(await runProfile({ name, profile })),
  );
  return server;
}

function configuredProfiles() {
  let profiles;
  try {
    profiles = JSON.parse(process.env.ASK_SECRET_PROFILES_JSON || '{}');
  } catch {
    throw new Error('ASK_SECRET_PROFILES_JSON must be valid JSON');
  }
  if (!profiles || Array.isArray(profiles) || typeof profiles !== 'object') {
    throw new Error('ASK_SECRET_PROFILES_JSON must be an object');
  }
  return profiles;
}

function runOpaque(name, executable, args = []) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, [process.env.SSS_RUN_BIN || DEFAULT_SSS_RUN, name, '--', executable, ...args], {
      env: { ...process.env, SSS_REQUIRE_AGE: '1' },
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    child.once('error', () => rejectRun(new Error('AskSecret runtime failed to start')));
    child.once('close', code => {
      if (code === 0) resolveRun(code);
      else rejectRun(new Error('AskSecret runtime failed'));
    });
  });
}

function probeOpaque(name) {
  return new Promise((resolveProbe, rejectProbe) => {
    const child = spawn(process.execPath, [process.env.SSS_GET_BIN || DEFAULT_SSS_GET, name], {
      env: { ...process.env, SSS_REQUIRE_AGE: '1', SSS_PROBE_ONLY: '1' },
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    child.once('error', () => rejectProbe(new Error('AskSecret runtime failed to start')));
    child.once('close', code => {
      if (code === 0) resolveProbe(code);
      else rejectProbe(new Error('secret is not ready for this runtime identity'));
    });
  });
}

export function createRuntimeOperations() {
  return {
    async probeSecret({ name }) {
      await probeOpaque(name);
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
      await runOpaque(name, selected.executable, args);
      return { status: 'completed', name, profile };
    },
  };
}

async function main() {
  const server = createAskSecretServer(createRuntimeOperations());
  await server.connect(new StdioServerTransport());
}

let invokedDirectly = false;
if (process.argv[1]) {
  try {
    invokedDirectly = realpathSync(process.argv[1]) === realpathSync(SELF);
  } catch {
    invokedDirectly = resolve(process.argv[1]) === resolve(SELF);
  }
}
if (invokedDirectly) {
  main().catch(error => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
