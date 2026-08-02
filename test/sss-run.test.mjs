import assert from 'node:assert/strict';
import { mkdtempSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { PassThrough, Writable } from 'node:stream';
import test from 'node:test';

import { parseArgs, pipeSecretToCommand } from '../bin/sss-run.mjs';

test('requires an explicit consumer after the secret name', () => {
  assert.throws(() => parseArgs(['api-token']), /usage/);
  assert.deepEqual(parseArgs(['api-token', '--', 'ssh', 'example']), {
    name: 'api-token',
    command: 'ssh',
    args: ['example'],
  });
});

test('runs its CLI main function through a PATH symlink', () => {
  const link = join(mkdtempSync(join(tmpdir(), 'sss-run-')), 'sss-run');
  symlinkSync(join(process.cwd(), 'bin', 'sss-run.mjs'), link);
  const result = spawnSync(link, [], { encoding: 'utf8' });

  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage: sss-run/);
});

test('pipes the decrypted bytes only to the consumer stdin', async () => {
  const source = new PassThrough();
  const received = [];
  const sink = new Writable({
    write(chunk, _encoding, callback) {
      received.push(chunk.toString('utf8'));
      callback();
    },
  });
  const child = { stdin: sink };

  await pipeSecretToCommand({
    secretStdout: source,
    spawnConsumer: () => child,
    command: 'ignored-by-test',
    args: [],
  }, async () => {
    source.end('not-written-to-parent-stdout');
  });

  assert.deepEqual(received, ['not-written-to-parent-stdout']);
});

test('reports a closed consumer stdin without an unhandled EPIPE', async () => {
  const source = new PassThrough();
  const sink = new Writable({
    write(_chunk, _encoding, callback) {
      callback(Object.assign(new Error('write EPIPE'), { code: 'EPIPE' }));
    },
  });

  await assert.rejects(
    pipeSecretToCommand({
      secretStdout: source,
      spawnConsumer: () => ({ stdin: sink }),
      command: 'ignored-by-test',
      args: [],
    }, async () => { source.end('never-to-stdout'); }),
    /EPIPE/,
  );
});
