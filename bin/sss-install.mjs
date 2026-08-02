#!/usr/bin/env node
// sss-install — npx entrypoint for one-shot install of simple-secret-storage.
//
// Run via:
//   npx -y github:megamen32/simple-secret-storage
//
// This script downloads the rest of the repo (npm install for npm
// packages) and then runs the bundled install.sh. We delegate to bash
// because the install needs sudo, systemd, and various shell utilities
// that are awkward to call from Node directly.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { chmodSync, existsSync, readFileSync } from 'node:fs';

const HERE = dirname(fileURLToPath(import.meta.url));
const INSTALL_SH = join(HERE, '..', 'install.sh');

if (!existsSync(INSTALL_SH)) {
  console.error('[sss-install] install.sh not found next to bin/');
  console.error('  looked in:', INSTALL_SH);
  process.exit(2);
}

// Make sure install.sh is executable — npm tarballs often strip +x.
try {
  chmodSync(INSTALL_SH, 0o755);
} catch (e) {
  // Non-fatal: on Windows or restricted FS the chmod may fail; the
  // spawn below uses `bash <file>` so the bit doesn't matter.
}

const result = spawnSync('bash', [INSTALL_SH, ...process.argv.slice(2)], {
  stdio: 'inherit',
});
process.exit(result.status ?? 1);