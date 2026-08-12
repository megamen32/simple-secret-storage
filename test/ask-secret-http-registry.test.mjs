import assert from 'node:assert/strict';
import test from 'node:test';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { registerAskSecretTools } from '../dist/ask-secret-tools.js';


test('HTTP server registry includes canonical AskSecret tools', async () => {
  const server = new McpServer({ name: 'ask-secret-http-fixture', version: '1.0.0' });
  registerAskSecretTools(server, {
    probeSecret: async ({ name }) => ({ status: 'ready', name }),
    runProfile: async ({ name, profile }) => ({ status: 'completed', name, profile }),
  });
  const client = new Client({ name: 'fixture', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map(tool => tool.name).sort(), ['ask_secret', 'ask_secret_run']);
  const result = await client.callTool({ name: 'ask_secret', arguments: { name: 'fixture' } });
  assert.match(result.content[0].text, /"status":"ready"/);
  await Promise.all([client.close(), server.close()]);
});
