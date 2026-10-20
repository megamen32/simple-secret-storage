import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import test from 'node:test';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

async function reservePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function waitUntilReady(url, child) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`SSS exited early with code ${child.exitCode}`);
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      // The listener may not be ready yet.
    }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('SSS did not become ready');
}

test('deleting a secret revokes its outstanding one-time decrypt URLs before name reuse', async t => {
  const home = mkdtempSync(join(tmpdir(), 'sss-decrypt-revocation-'));
  const port = await reservePort();
  const apiKey = 'test-only-api-key';
  const origin = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['dist/server.js'], {
    cwd: new URL('..', import.meta.url),
    env: {
      ...process.env,
      HOME: home,
      SSS_API_KEY: apiKey,
      SSS_PORT: String(port),
      SSS_SERVER_URL: origin,
    },
    stdio: 'ignore',
  });
  t.after(() => child.kill('SIGTERM'));

  await waitUntilReady(`${origin}/`, child);

  const headers = { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' };
  const transport = new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), {
    requestInit: { headers: { authorization: `Bearer ${apiKey}` } },
  });
  const client = new Client({ name: 'sss-decrypt-revocation-test', version: '1.0.0' });
  await client.connect(transport);
  t.after(async () => {
    await client.close();
  });

  const name = 'delete_revocation_fixture';
  const deleteAlias = 'delete revocation fixture';
  const create = async (value, secretName = name) => {
    const response = await fetch(`${origin}/api/secrets`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ name: secretName, value }),
    });
    assert.equal(response.status, 200);
  };
  const urlFromGetSecret = async (secretName = name) => {
    const result = await client.callTool({ name: 'get_secret', arguments: { name: secretName } });
    const text = result.content[0].text;
    const url = text.match(/https?:\/\/[^\s'"<>]+\/d\/([a-f0-9]{32})/)?.[0];
    assert.ok(url, 'get_secret did not return a one-time decrypt URL');
    return url;
  };
  const assertRevoked = async url => {
    const response = await fetch(url);
    const body = await response.text();
    assert.equal(response.status, 410, 'deleted secret left a usable decrypt capability');
    assert.equal(body, 'Token expired or not found');
  };
  const assertDelivers = async (url, expectedValue) => {
    const response = await fetch(url);
    assert.equal(response.status, 200);
    const encoded = await response.text();
    assert.equal(Buffer.from(encoded, 'base64').toString('utf8'), expectedValue);
  };

  await create('original-test-only-value');
  const restDeleteUrl = await urlFromGetSecret();
  const restDelete = await fetch(`${origin}/api/secrets/${encodeURIComponent(deleteAlias)}`, {
    method: 'DELETE',
    headers: { authorization: `Bearer ${apiKey}` },
  });
  assert.equal(restDelete.status, 200);
  await create('replacement-test-only-value');
  await assertRevoked(restDeleteUrl);

  const mcpDeleteUrl = await urlFromGetSecret();
  const deleted = await client.callTool({ name: 'delete_secret', arguments: { name: deleteAlias } });
  assert.match(deleted.content[0].text, /Deleted/);
  await create('second-replacement-test-only-value');
  await assertRevoked(mcpDeleteUrl);

  const restRenameUrl = await urlFromGetSecret(deleteAlias);
  const restRename = await fetch(`${origin}/api/secrets/${encodeURIComponent(name)}/rename`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ name: 'rest_renamed_fixture' }),
  });
  assert.equal(restRename.status, 200);
  await create('reused-old-name-after-rest-rename');
  await assertDelivers(restRenameUrl, 'second-replacement-test-only-value');

  await create('mcp-rename-original-test-value', 'mcp_rename_fixture');
  const mcpRenameUrl = await urlFromGetSecret('mcp rename fixture');
  const mcpRename = await client.callTool({
    name: 'rename_secret',
    arguments: { name: 'mcp_rename_fixture', new_name: 'mcp_renamed_fixture' },
  });
  assert.match(mcpRename.content[0].text, /Renamed/);
  await create('reused-old-name-after-mcp-rename', 'mcp_rename_fixture');
  await assertDelivers(mcpRenameUrl, 'mcp-rename-original-test-value');

  const restMissingSelfRename = await fetch(`${origin}/api/secrets/missing_self_rename_fixture/rename`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ name: 'missing_self_rename_fixture' }),
  });
  assert.equal(restMissingSelfRename.status, 404);

  const mcpMissingSelfRename = await client.callTool({
    name: 'rename_secret',
    arguments: { name: 'missing_self_rename_fixture', new_name: 'missing_self_rename_fixture' },
  });
  assert.match(mcpMissingSelfRename.content[0].text, /Not found/);
});
