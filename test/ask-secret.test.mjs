import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import test from 'node:test';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

test('stdio MCP identifies as SSS and keeps the retrieval/run-only AskSecret entrypoint', async () => {
  const entrypoint = new URL('../bin/ask-secret-mcp.mjs', import.meta.url);
  assert.equal(
    existsSync(entrypoint),
    true,
    'narrow retrieval/run-only AskSecret entrypoint is absent',
  );

  const { createAskSecretServer } = await import(entrypoint.href);
  const server = createAskSecretServer({
    probeSecret: async () => ({ status: 'ready' }),
    runProfile: async () => ({ status: 'completed', output: 'ok' }),
  });
  const client = new Client({ name: 'ask-secret-contract-test', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  assert.equal(client.getServerVersion()?.name, 'simple-secret-storage');
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map(tool => tool.name).sort(), ['ask_secret', 'ask_secret_run']);
  const serialized = JSON.stringify(listed.tools);
  for (const forbidden of ['list_secrets', 'delete_secret', 'register_agent', 'agent_id', 'base64', 'command', 'args']) {
    assert.doesNotMatch(serialized, new RegExp(forbidden));
  }
  assert.match(serialized, /profile/);

  await Promise.all([client.close(), server.close()]);
});
