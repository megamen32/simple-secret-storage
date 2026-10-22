import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { createServer } from 'node:http'
import { readFile, mkdtemp, mkdir, writeFile, chmod, stat, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import test from 'node:test'

import { loadExistingAgentIdentity } from '../src/agent-identity.mjs'

const UID = 1000
const IDENTITY_JSON = JSON.stringify({
  agent_id: 'synthetic-test-agent',
  secretKey: 'synthetic-not-a-credential',
  publicKey: 'age1synthetic',
  created: '2026-10-23T00:00:00.000Z',
})

function fakeFs({ mode = 0o100600, uid = UID, chmodError = null } = {}) {
  const state = { mode, chmodCalls: [], readCalls: 0 }
  const fsImpl = {
    lstatSync() {
      return {
        mode: state.mode,
        uid,
        isFile: () => (state.mode & 0o170000) === 0o100000,
        isSymbolicLink: () => (state.mode & 0o170000) === 0o120000,
      }
    },
    chmodSync(path, mode) {
      state.chmodCalls.push([path, mode])
      if (chmodError) throw chmodError
      state.mode = (state.mode & ~0o777) | mode
    },
    readFileSync(_path, encoding) {
      state.readCalls += 1
      assert.equal(encoding, 'utf8')
      return IDENTITY_JSON
    },
  }
  return { fsImpl, state }
}

test('secure owner-owned 0600 identity is read without chmod metadata write', () => {
  const { fsImpl, state } = fakeFs({ mode: 0o100600 })
  const result = loadExistingAgentIdentity('/home/owner/.config/sss-mcp/agent-identity.json', { fsImpl, uid: UID })

  assert.equal(result.agent_id, 'synthetic-test-agent')
  assert.deepEqual(state.chmodCalls, [])
  assert.equal(state.readCalls, 1)
})

test('unsafe mode is tightened to 0600 before the identity is read', () => {
  const { fsImpl, state } = fakeFs({ mode: 0o100644 })
  const result = loadExistingAgentIdentity('/home/owner/.config/sss-mcp/agent-identity.json', { fsImpl, uid: UID })

  assert.equal(result.agent_id, 'synthetic-test-agent')
  assert.deepEqual(state.chmodCalls, [['/home/owner/.config/sss-mcp/agent-identity.json', 0o600]])
  assert.equal(state.mode & 0o777, 0o600)
  assert.equal(state.readCalls, 1)
})

test('unsafe mode that cannot be repaired in a read-only home fails before reading', () => {
  const { fsImpl, state } = fakeFs({ mode: 0o100644, chmodError: Object.assign(new Error('read-only fixture'), { code: 'EROFS' }) })

  assert.throws(() => loadExistingAgentIdentity('/home/owner/.config/sss-mcp/agent-identity.json', { fsImpl, uid: UID }), { code: 'EROFS' })
  assert.equal(state.chmodCalls.length, 1)
  assert.equal(state.readCalls, 0)
})

test('symlink identity fails closed without chmod or following the target', () => {
  const { fsImpl, state } = fakeFs({ mode: 0o120777 })

  assert.throws(() => loadExistingAgentIdentity('/home/owner/.config/sss-mcp/agent-identity.json', { fsImpl, uid: UID }), /regular file owned/)
  assert.equal(state.chmodCalls.length, 0)
  assert.equal(state.readCalls, 0)
})

test('identity owned by another user fails closed without chmod or reading', () => {
  const { fsImpl, state } = fakeFs({ mode: 0o100600, uid: UID + 1 })

  assert.throws(() => loadExistingAgentIdentity('/home/owner/.config/sss-mcp/agent-identity.json', { fsImpl, uid: UID }), /regular file owned/)
  assert.equal(state.chmodCalls.length, 0)
  assert.equal(state.readCalls, 0)
})

const packageRoot = process.cwd()
const require = createRequire(join(packageRoot, 'package.json'))
const ageModule = await import(require.resolve('age-encryption'))
const { Encrypter, armor, generateX25519Identity, identityToRecipient } = ageModule
const sssRoot = process.env.SSS_TEST_SOURCE_ROOT || packageRoot
const SSS_RUN = join(sssRoot, 'bin', 'sss-run.mjs')
const SSS_GET = join(sssRoot, 'bin', 'sss-get.mjs')
const SYNTHETIC_NAME = 'synthetic-readonly-chain-fixture'
const SYNTHETIC_SECRET = 'synthetic-only-chain-value-20261023'
const SYNTHETIC_API_KEY = 'synthetic-only-api-key'

async function ensureIdentityHome() {
  if (process.env.SSS_TEST_HOME) {
    const home = process.env.SSS_TEST_HOME
    const identityPath = join(home, '.config', 'sss-mcp', 'agent-identity.json')
    const identity = JSON.parse(await readFile(identityPath, 'utf8'))
    const info = await stat(identityPath)
    assert.equal(info.uid, process.getuid())
    assert.equal(info.mode & 0o777, 0o600)
    return { home, identity, cleanup: async () => {} }
  }

  const home = await mkdtemp(join(tmpdir(), 'sss-chain-home-'))
  await chmod(home, 0o700)
  const identityDir = join(home, '.config', 'sss-mcp')
  await mkdir(identityDir, { recursive: true, mode: 0o700 })
  const secretKey = await generateX25519Identity()
  const publicKey = await identityToRecipient(secretKey)
  const identity = { agent_id: 'synthetic-sss-readonly-test', secretKey, publicKey, created: '2026-10-23T00:00:00.000Z' }
  await writeFile(join(identityDir, 'agent-identity.json'), JSON.stringify(identity), { flag: 'wx', mode: 0o600 })
  return { home, identity, cleanup: () => rm(home, { recursive: true, force: true }) }
}

function sendJson(res, body, headers = {}) {
  res.writeHead(200, { 'Content-Type': 'application/json', ...headers })
  res.end(JSON.stringify(body))
}

async function readJson(req) {
  let body = ''
  for await (const chunk of req) body += chunk
  return JSON.parse(body)
}

async function startFakeSss(publicKey) {
  const encrypter = new Encrypter()
  encrypter.addRecipient(publicKey)
  const encryptedSecret = armor.encode(await encrypter.encrypt(SYNTHETIC_SECRET))
  const counts = { initialize: 0, register_agent: 0, get_secret: 0, download: 0 }
  const server = createServer(async (req, res) => {
    if (req.method === 'POST' && req.url === '/mcp') {
      const envelope = await readJson(req)
      if (req.headers.authorization !== `Bearer ${SYNTHETIC_API_KEY}`) {
        res.writeHead(401).end()
        return
      }
      if (envelope.method === 'initialize') {
        counts.initialize += 1
        return sendJson(res, { jsonrpc: '2.0', id: envelope.id, result: { protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'local-fixture', version: '1' } } }, { 'Mcp-Session-Id': 'synthetic-session' })
      }
      if (envelope.method === 'notifications/initialized') {
        res.writeHead(204).end()
        return
      }
      if (envelope.method !== 'tools/call') {
        res.writeHead(400).end()
        return
      }
      const { name, arguments: args } = envelope.params
      if (name === 'register_agent') {
        counts.register_agent += 1
        assert.equal(args.agent_id, 'synthetic-sss-readonly-test')
        assert.equal(args.public_key, publicKey)
        return sendJson(res, { jsonrpc: '2.0', id: envelope.id, result: { content: [{ type: 'text', text: 'registered' }] } })
      }
      if (name === 'get_secret') {
        counts.get_secret += 1
        assert.equal(args.name, SYNTHETIC_NAME)
        assert.equal(args.agent_id, 'synthetic-sss-readonly-test')
        return sendJson(res, { jsonrpc: '2.0', id: envelope.id, result: { content: [{ type: 'text', text: `http://127.0.0.1:${server.address().port}/d/0123456789abcdef0123456789abcdef` }] } })
      }
      res.writeHead(404).end()
      return
    }
    if (req.method === 'GET' && req.url === '/d/0123456789abcdef0123456789abcdef') {
      counts.download += 1
      res.writeHead(200, { 'Content-Type': 'application/vnd.age' })
      res.end(encryptedSecret)
      return
    }
    res.writeHead(404).end()
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  return { server, counts, url: `http://127.0.0.1:${server.address().port}` }
}

function runConsumerChain({ home, url }) {
  const expectedHash = createHash('sha256').update(SYNTHETIC_SECRET).digest('hex')
  const consumerCode = `import {createHash} from 'node:crypto'; const chunks=[]; for await (const chunk of process.stdin) chunks.push(chunk); const hash=createHash('sha256').update(Buffer.concat(chunks)).digest('hex'); process.exitCode=hash===process.env.SSS_TEST_EXPECTED_SHA256?0:7;`
  const env = {
    PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
    HOME: home,
    SSS_URL: url,
    SSS_API_KEY: SYNTHETIC_API_KEY,
    SSS_AGENT_ID: 'synthetic-sss-readonly-test',
    SSS_AGENT_LABEL: 'synthetic-only',
    SSS_REQUIRE_AGE: '1',
    SSS_TEST_EXPECTED_SHA256: expectedHash,
  }
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SSS_RUN, SYNTHETIC_NAME, '--', process.execPath, '--input-type=module', '-e', consumerCode], { env, stdio: ['ignore', 'pipe', 'pipe'] })
    const stdout = []
    const stderr = []
    child.stdout.on('data', chunk => stdout.push(chunk))
    child.stderr.on('data', chunk => stderr.push(chunk))
    child.once('error', reject)
    child.once('close', (code, signal) => resolve({ code, signal, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() }))
  })
}

test('sss-get age decrypt flows through sss-run stdin to a fake consumer with an existing private identity', async () => {
  const { home, identity, cleanup } = await ensureIdentityHome()
  const fakeSss = await startFakeSss(identity.publicKey)
  try {
    const result = await runConsumerChain({ home, url: fakeSss.url })
    assert.equal(result.code, 0, result.stderr)
    assert.equal(result.stdout, '')
    assert.equal(result.stderr, '')
    assert.deepEqual(fakeSss.counts, { initialize: 1, register_agent: 1, get_secret: 1, download: 1 })
    const identityInfo = await stat(join(home, '.config', 'sss-mcp', 'agent-identity.json'))
    assert.equal(identityInfo.mode & 0o777, 0o600)
  } finally {
    await new Promise(resolve => fakeSss.server.close(resolve))
    await cleanup()
  }
})
