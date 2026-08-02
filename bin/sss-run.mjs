#!/usr/bin/env node
// sss-run — deliver one SSS secret directly to a local consumer's stdin.
// The decrypted value is never written to this process's stdout, argv, or env.

import { spawn } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';

const HERE = dirname(fileURLToPath(import.meta.url));
const GETTER = join(HERE, 'sss-get.mjs');
const USAGE = 'usage: sss-run <secret-name> -- <consumer> [args...]';

export function parseArgs(argv) {
  const divider = argv.indexOf('--');
  const name = argv[0];
  const command = divider >= 0 ? argv[divider + 1] : undefined;
  if (!name || divider !== 1 || !command) throw new Error(USAGE);
  return { name, command, args: argv.slice(divider + 2) };
}

/**
 * Pipe secret bytes to the consumer's stdin. `writeSecret` lets the unit test
 * drive the source without ever putting a secret in the parent process output.
 */
export async function pipeSecretToCommand(
  { secretStdout, spawnConsumer = spawn, command, args },
  writeSecret,
) {
  const child = spawnConsumer(command, args, { stdio: ['pipe', 'inherit', 'inherit'] });
  if (!child?.stdin || typeof child.stdin.write !== 'function') {
    throw new Error('secret consumer has no writable stdin');
  }
  const completed = once(child.stdin, 'finish');
  try {
    await writeSecret(child);
    secretStdout.pipe(child.stdin);
    await completed;
  } catch (error) {
    secretStdout.unpipe(child.stdin);
    // `completed` is already observing the stream error. Consume its rejection
    // when the first write fails so Node does not turn it into an unhandled one.
    void completed.catch(() => {});
    child.stdin.destroy();
    throw error;
  }
  return child;
}

async function waitForFirstSecretByte(stream, producer) {
  const first = await Promise.race([
    once(stream, 'data').then(([chunk]) => chunk),
    once(producer, 'close').then(([code]) => {
      throw new Error(`sss-get exited before producing a secret (code ${code ?? 'unknown'})`);
    }),
    once(producer, 'error').then(([error]) => { throw error; }),
  ]);
  if (!first?.length) throw new Error('sss-get produced an empty secret');
  return first;
}

function exitCode(child, label) {
  return once(child, 'close').then(([code, signal]) => {
    if (code !== 0) throw new Error(`${label} failed (${signal ? `signal ${signal}` : `exit ${code}`})`);
  });
}

async function main() {
  let parsed;
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
    return;
  }

  const producer = spawn(process.execPath, [GETTER, parsed.name], {
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  // Register before the first readable chunk: a short secret producer may exit
  // before the consumer's stdin is drained.
  const producerDone = exitCode(producer, 'sss-get').then(() => null, (error) => error);
  try {
    const first = await waitForFirstSecretByte(producer.stdout, producer);
    const consumer = await pipeSecretToCommand(
      { secretStdout: producer.stdout, command: parsed.command, args: parsed.args },
      async (child) => { await consumerWrite(child, first); },
    );
    const [producerError] = await Promise.all([producerDone, exitCode(consumer, 'secret consumer')]);
    if (producerError) throw producerError;
  } catch (error) {
    console.error(`sss-run: ${error.message}`);
    process.exitCode = 1;
  }
}

function consumerWrite(consumer, first) {
  // Secrets used by this MVP are credential-sized. One bounded buffered write
  // avoids a second drain promise racing the stdin error handler.
  if (first.length > 64 * 1024) throw new Error('secret is too large for sss-run');
  consumer.stdin.write(first);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === realpathSync(process.argv[1])) {
  await main();
}
