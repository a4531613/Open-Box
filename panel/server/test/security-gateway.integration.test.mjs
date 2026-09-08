import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtemp, mkdir, rm } from 'node:fs/promises'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const serverDir = path.resolve(here, '..')

const getFreePort = async () => {
  const server = http.createServer()
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const address = server.address()
  const port = typeof address === 'object' && address ? address.port : 0
  await new Promise((resolve) => server.close(resolve))
  if (!port) throw new Error('failed to allocate ephemeral port')
  return port
}

const waitForHealth = async (baseUrl, child, logs) => {
  for (let i = 0; i < 80; i += 1) {
    if (child.exitCode !== null) {
      throw new Error(`gateway exited early (${child.exitCode})\n${logs.join('')}`)
    }
    try {
      const response = await fetch(`${baseUrl}/api/health`)
      if (response.ok) return
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(`gateway did not become healthy\n${logs.join('')}`)
}

const stopChild = async (child) => {
  if (child.exitCode !== null) return
  child.kill('SIGTERM')
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 1500)),
  ])
  if (child.exitCode === null) child.kill('SIGKILL')
}

const startGateway = async ({ seed } = {}) => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'openbox-gateway-test-'))
  const dataDir = path.join(tempDir, 'data')
  await mkdir(dataDir, { recursive: true })
  const dbPath = path.join(dataDir, 'openbox.sqlite')

  if (seed) {
    const db = new DatabaseSync(dbPath)
    db.exec(`
      CREATE TABLE IF NOT EXISTS app_storage (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `)
    for (const [key, value] of Object.entries(seed)) {
      db.prepare('INSERT INTO app_storage(key, value) VALUES (?, ?)').run(key, String(value))
    }
    db.close()
  }

  const gatewayPort = await getFreePort()
  const backendPort = await getFreePort()
  const logs = []
  const child = spawn(process.execPath, ['security-gateway.mjs'], {
    cwd: serverDir,
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      PORT: String(gatewayPort),
      OPENBOX_BACKEND_PORT: String(backendPort),
      OPENBOX_ROOT: tempDir,
      ZASHBOARD_DB_PATH: dbPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stdout.on('data', (chunk) => logs.push(String(chunk)))
  child.stderr.on('data', (chunk) => logs.push(String(chunk)))

  const baseUrl = `http://127.0.0.1:${gatewayPort}`
  await waitForHealth(baseUrl, child, logs)

  return {
    baseUrl,
    child,
    dbPath,
    logs,
    cleanup: async () => {
      await stopChild(child)
      await rm(tempDir, { recursive: true, force: true })
    },
  }
}

const jsonRequest = (url, body, cookie) => fetch(url, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    ...(cookie ? { cookie } : {}),
  },
  body: JSON.stringify(body),
})

const cookieFrom = (response) => {
  const value = response.headers.get('set-cookie') || ''
  return value.split(';')[0]
}

test('gateway hides backend details and blocks unauthenticated/change-password controller abuse', async (t) => {
  const gateway = await startGateway()
  t.after(gateway.cleanup)

  const health = await fetch(`${gateway.baseUrl}/api/health`)
  assert.equal(health.status, 200)
  assert.deepEqual(await health.json(), { ok: true })
  assert.equal(health.headers.get('x-powered-by'), null)
  assert.equal(health.headers.get('x-content-type-options'), 'nosniff')

  const setup = await jsonRequest(`${gateway.baseUrl}/api/auth/setup`, { password: 'correct-horse-battery-staple' })
  assert.equal(setup.status, 200)
  const cookie = cookieFrom(setup)
  assert.match(cookie, /^openbox_secure_session=/)

  const anonymousChange = await jsonRequest(`${gateway.baseUrl}/api/auth/change-password`, {
    currentPassword: 'correct-horse-battery-staple',
    newPassword: 'another-long-password',
  })
  assert.equal(anonymousChange.status, 401)

  const noAuth = await fetch(`${gateway.baseUrl}/api/storage`)
  assert.equal(noAuth.status, 401)

  const customController = await fetch(`${gateway.baseUrl}/api/controller/version`, {
    headers: {
      cookie,
      'x-zashboard-target-base': 'http://127.0.0.1:22',
    },
  })
  assert.equal(customController.status, 400)
  assert.equal((await customController.json()).error, 'CUSTOM_CONTROLLER_TARGET_DISABLED')

  const queryController = await fetch(`${gateway.baseUrl}/api/controller/version?targetBase=http://127.0.0.1:22`, {
    headers: { cookie },
  })
  assert.equal(queryController.status, 400)
})

test('gateway rate-limits repeated bad passwords', async (t) => {
  const gateway = await startGateway()
  t.after(gateway.cleanup)

  const setup = await jsonRequest(`${gateway.baseUrl}/api/auth/setup`, { password: 'rate-limit-password' })
  assert.equal(setup.status, 200)

  for (let i = 0; i < 5; i += 1) {
    const response = await jsonRequest(`${gateway.baseUrl}/api/auth/login`, { password: `wrong-${i}` })
    assert.equal(response.status, 401)
  }
  const blocked = await jsonRequest(`${gateway.baseUrl}/api/auth/login`, { password: 'rate-limit-password' })
  assert.equal(blocked.status, 429)
  assert.ok(Number(blocked.headers.get('retry-after')) > 0)
})

test('legacy plaintext password is migrated to scrypt and replaced by an internal backend secret', async (t) => {
  const legacyPassword = 'legacy-password-123'
  const gateway = await startGateway({
    seed: {
      'config/access-password': legacyPassword,
      'config/access-password-enabled': 'true',
    },
  })
  t.after(gateway.cleanup)

  const login = await jsonRequest(`${gateway.baseUrl}/api/auth/login`, { password: legacyPassword })
  assert.equal(login.status, 200)

  await stopChild(gateway.child)
  const db = new DatabaseSync(gateway.dbPath)
  const get = db.prepare('SELECT value FROM app_storage WHERE key = ?')
  const hash = get.get('config/access-password-scrypt')?.value || ''
  const legacySlot = get.get('config/access-password')?.value || ''
  db.close()

  assert.match(hash, /^scrypt-v1\$/)
  assert.notEqual(legacySlot, legacyPassword)
  assert.ok(legacySlot.length >= 40)
})
