#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createRuntimeOperations, registerAskSecretTools } from '../dist/ask-secret-tools.js';

// HTTP and stdio share one schema: the form tool never retrieves secret bytes.
export { createRuntimeOperations };
export function createAskSecretServer({ probeSecret, runProfile }) {
  if (typeof probeSecret !== 'function' || typeof runProfile !== 'function') {
    throw new TypeError('AskSecret requires probeSecret and runProfile operations');
  }
  const server = new McpServer({ name: 'ask-secret', version: '1.0.0' });
  registerAskSecretTools(server, {probeSecret, runProfile});
  return server;
}
let invokedDirectly = false;
if (process.argv[1]) {
  try { invokedDirectly = realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); }
  catch { invokedDirectly = resolve(process.argv[1]) === fileURLToPath(import.meta.url); }
}
if (invokedDirectly) {
  createAskSecretServer(createRuntimeOperations()).connect(new StdioServerTransport()).catch(() => {
    console.error('AskSecret runtime failed to start');
    process.exitCode = 1;
  });
}
