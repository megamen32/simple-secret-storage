import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import test from 'node:test';

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
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // The listener may not be ready yet.
    }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('SSS did not become ready');
}

test('passwordless /secret form stores a value and returns an opaque id', async t => {
  const home = mkdtempSync(join(tmpdir(), 'sss-public-secret-'));
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

  const page = await fetch(`${origin}/secret`);
  assert.equal(page.status, 200);
  assert.match(page.headers.get('cache-control') ?? '', /no-store/);
  const pageHtml = await page.text();
  assert.match(pageHtml, /<form[^>]+method=post[^>]+action="\/secret"/i);
  assert.match(pageHtml, /name=value/);
  assert.doesNotMatch(pageHtml, /name=(?:"|')?(?:password|token|key)(?:"|')?/i);

  const value = 'known-test-fixture-value';
  const saved = await fetch(`${origin}/secret`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ value }),
  });
  assert.equal(saved.status, 201);
  assert.match(saved.headers.get('cache-control') ?? '', /no-store/);
  const savedHtml = await saved.text();
  assert.doesNotMatch(savedHtml, new RegExp(value));
  const id = savedHtml.match(/id="secret-id">([a-f0-9-]{36})<\/code>/i)?.[1];
  assert.ok(id, 'response did not contain an opaque secret id');

  const listed = await fetch(`${origin}/api/secrets`, {
    headers: { authorization: `Bearer ${apiKey}` },
  });
  assert.equal(listed.status, 200);
  const payload = await listed.json();
  assert.ok(payload.secrets.some(secret => secret.name === id));

  const nginx = readFileSync(new URL('../nginx/pswd.bezrabotnyi.com.conf', import.meta.url), 'utf8');
  assert.match(nginx, /location = \/secret\s*\{/);
});
