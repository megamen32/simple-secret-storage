import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import test from 'node:test';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

test('stdio MCP identifies as SSS and exposes safe secret handoff discovery', async () => {
  const entrypoint = new URL('../bin/ask-secret-mcp.mjs', import.meta.url);
  assert.equal(
    existsSync(entrypoint),
    true,
    'narrow retrieval/run-only AskSecret entrypoint is absent',
  );

  const { createAskSecretServer } = await import(entrypoint.href);
  const server = createAskSecretServer({
    probeSecret: async () => ({ status: 'ready' }),
    listProfiles: async () => ({ profiles: [] }),
    runProfile: async () => ({ status: 'completed', output: 'ok' }),
  });
  const client = new Client({ name: 'ask-secret-contract-test', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  assert.equal(client.getServerVersion()?.name, 'simple-secret-storage');
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map(tool => tool.name).sort(), [
    'ask_secret',
    'ask_secret_run',
    'list_secret_run_profiles',
  ]);
  const serialized = JSON.stringify(listed.tools);
  for (const forbidden of ['list_secrets', 'delete_secret', 'register_agent', 'agent_id', 'base64']) {
    assert.doesNotMatch(serialized, new RegExp(forbidden));
  }
  const runTool = listed.tools.find(tool => tool.name === 'ask_secret_run');
  assert.deepEqual(Object.keys(runTool.inputSchema.properties).sort(), ['name', 'profile']);
  assert.match(serialized, /user-facing assistant message/);
  assert.match(serialized, /many harnesses hide MCP tool output/);
  assert.match(serialized, /list_secret_run_profiles/);
  const profiles = await client.callTool({ name: 'list_secret_run_profiles', arguments: {} });
  assert.equal(profiles.content[0].text, '{"profiles":[]}');

  await Promise.all([client.close(), server.close()]);
});
