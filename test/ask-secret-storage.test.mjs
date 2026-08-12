import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

test('a provisioned agent identity cannot be replaced through legacy registration', async () => {
  const originalHome = process.env.HOME;
  process.env.HOME = mkdtempSync(join(tmpdir(), 'ask-secret-home-'));
  try {
    const { Storage } = await import(`../dist/storage.js?immutable=${Date.now()}`);
    const storage = new Storage();
    storage.registerAgent('runtime-agent', 'age1first');
    assert.throws(() => storage.registerAgent('runtime-agent', 'age1replacement'), /cannot be replaced/);
    assert.equal(storage.getAgent('runtime-agent').publicKey, 'age1first');
  } finally {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
  }
});
