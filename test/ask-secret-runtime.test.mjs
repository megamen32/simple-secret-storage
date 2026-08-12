import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createRuntimeOperations } from '../bin/ask-secret-mcp.mjs';

test('runtime maps a named profile to sss-run without accepting a caller command', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'ask-secret-runtime-'));
  const fakeRun = join(cwd, 'fake-sss-run.mjs');
  const fakeGet = join(cwd, 'fake-sss-get.mjs');
  const receipt = join(cwd, 'receipt.json');
  const probeReceipt = join(cwd, 'probe.json');
  writeFileSync(fakeRun, `import { writeFileSync } from 'node:fs';\nwriteFileSync(process.env.RECEIPT, JSON.stringify({argv: process.argv.slice(2), requireAge: process.env.SSS_REQUIRE_AGE}));\n`);
  writeFileSync(fakeGet, `import { writeFileSync } from 'node:fs';\nwriteFileSync(process.env.PROBE_RECEIPT, JSON.stringify({argv: process.argv.slice(2), probeOnly: process.env.SSS_PROBE_ONLY, requireAge: process.env.SSS_REQUIRE_AGE}));\n`);
  const previous = {
    SSS_RUN_BIN: process.env.SSS_RUN_BIN,
    SSS_GET_BIN: process.env.SSS_GET_BIN,
    ASK_SECRET_PROFILES_JSON: process.env.ASK_SECRET_PROFILES_JSON,
    RECEIPT: process.env.RECEIPT,
    PROBE_RECEIPT: process.env.PROBE_RECEIPT,
  };
  process.env.SSS_RUN_BIN = fakeRun;
  process.env.SSS_GET_BIN = fakeGet;
  process.env.ASK_SECRET_PROFILES_JSON = JSON.stringify({ canary: { executable: '/usr/bin/true', args: ['fixed'] } });
  process.env.RECEIPT = receipt;
  process.env.PROBE_RECEIPT = probeReceipt;
  try {
    const operations = createRuntimeOperations();
    assert.deepEqual(await operations.probeSecret({ name: 'demo' }), { status: 'ready', name: 'demo' });
    const probed = JSON.parse(await import('node:fs').then(({ readFileSync }) => readFileSync(probeReceipt, 'utf8')));
    assert.deepEqual(probed, { argv: ['demo'], probeOnly: '1', requireAge: '1' });
    assert.deepEqual(await operations.runProfile({ name: 'demo', profile: 'canary' }), { status: 'completed', name: 'demo', profile: 'canary' });
    const received = JSON.parse(await import('node:fs').then(({ readFileSync }) => readFileSync(receipt, 'utf8')));
    assert.deepEqual(received.argv, ['demo', '--', '/usr/bin/true', 'fixed']);
    assert.equal(received.requireAge, '1');
    await assert.rejects(operations.runProfile({ name: 'demo', profile: 'missing' }), /unknown AskSecret profile/);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
