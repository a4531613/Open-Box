import express from 'express'
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import http from 'node:http'
import { DatabaseSync } from 'node:sqlite'
import { WebSocket, WebSocketServer } from 'ws'
import { createLoginLimiter, hashPassword, verifyPassword } from './security-auth.mjs'

const gatewayHost = process.env.HOST || '127.0.0.1'
const gatewayPort = Number(process.env.PORT || 2026)
const backendPort = Number(process.env.OPENBOX_BACKEND_PORT || 2027)
const dbPath = process.env.ZASHBOARD_DB_PATH || '/opt/open-box/data/openbox.sqlite'
const cookieSecureOverride = process.env.OPENBOX_COOKIE_SECURE === '1'

const ACCESS_PASSWORD_ENABLED_KEY = 'config/access-password-enabled'
const ACCESS_PASSWORD_KEY = 'config/access-password'
const SECURE_PASSWORD_HASH_KEY = 'config/access-password-scrypt'
const INTERNAL_PASSWORD_KEY = 'openbox/gateway-internal-password'
const SESSION_COOKIE_NAME = 'openbox_secure_session'
const SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000
const MIN_PASSWORD_LENGTH = 8
const LOGIN_LIMITER = createLoginLimiter()
const sessionSecret = randomBytes(32)

const db = new DatabaseSync(dbPath)
db.exec(`
  CREATE TABLE IF NOT EXISTS app_storage (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`)
const getValueStatement = db.prepare('SELECT value FROM app_storage WHERE key = ?')
const setValueStatement = db.prepare(`
  INSERT INTO app_storage (key, value, updated_at)
  VALUES (?, ?, CURRENT_TIMESTAMP)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
`)

const getValue = (key) => getValueStatement.get(key)?.value ?? ''
const setValue = (key, value) => setValueStatement.run(key, String(value))
const parseStoredString = (value) => {
  if (typeof value !== 'string' || !value) return ''
  if (value.startsWith('"') && value.endsWith('"')) {
    try {
      const parsed = JSON.parse(value)
      if (typeof parsed === 'string') return parsed
    } catch {}
  }
  return value
}

const existingUserPassword = parseStoredString(getValue(ACCESS_PASSWORD_KEY))
let passwordHash = parseStoredString(getValue(SECURE_PASSWORD_HASH_KEY))
let internalPassword = parseStoredString(getValue(INTERNAL_PASSWORD_KEY))

if (!internalPassword) {
  internalPassword = randomBytes(48).toString('base64url')
  setValue(INTERNAL_PASSWORD_KEY, internalPassword)
}
if (!passwordHash && existingUserPassword && existingUserPassword !== internalPassword) {
  passwordHash = hashPassword(existingUserPassword)
  setValue(SECURE_PASSWORD_HASH_KEY, passwordHash)
}

// The original backend is loopback-only. Its legacy plaintext credential is replaced by a
// random internal secret; the user's actual password is retained only as a scrypt hash.
setValue(ACCESS_PASSWORD_KEY, internalPassword)
setValue(ACCESS_PASSWORD_ENABLED_KEY, 'true')

const safeStringEqual = (left, right) => {
  if (typeof left !== 'string' || typeof right !== 'string') return false
  const a = Buffer.from(left)
  const b = Buffer.from(right)
  return a.length === b.length && timingSafeEqual(a, b)
}

const parseCookies = (header) => {
  const map = new Map()
  if (typeof header !== 'string') return map
  for (const part of header.split(';')) {
    const idx = part.indexOf('=')
    if (idx <= 0) continue
    const key = part.slice(0, idx).trim()
    let value = part.slice(idx + 1).trim()
    try { value = decodeURIComponent(value) } catch {}
    if (key) map.set(key, value)
  }
  return map
}

const sessionToken = () => createHmac('sha256', sessionSecret).update(passwordHash || '').digest('base64url')
const isAuthenticated = (req) => {
  if (!passwordHash) return false
  const token = parseCookies(req.headers.cookie).get(SESSION_COOKIE_NAME)
  return token ? safeStringEqual(token, sessionToken()) : false
}
const requestUsesHttps = (req) => cookieSecureOverride || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https'
const setSessionCookie = (req, res) => res.cookie(SESSION_COOKIE_NAME, sessionToken(), {
  httpOnly: true,
  sameSite: 'strict',
  secure: requestUsesHttps(req),
  maxAge: SESSION_MAX_AGE_MS,
  path: '/',
})
const clearSessionCookie = (req, res) => res.clearCookie(SESSION_COOKIE_NAME, {
  httpOnly: true,
  sameSite: 'strict',
  secure: requestUsesHttps(req),
  path: '/',
})
const clientKey = (req) => String(req.socket.remoteAddress || req.ip || 'unknown')

// Start the upstream backend on loopback only. This preserves upstream compatibility while
// keeping the root-capable backend outside the LAN/WAN attack surface.
process.env.HOST = '127.0.0.1'
process.env.PORT = String(backendPort)
const backend = await import('./index.mjs')
await backend.startServer()

const backendBase = `http://127.0.0.1:${backendPort}`
const loginBackend = async () => {
  const response = await fetch(`${backendBase}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: internalPassword }),
  })
  if (!response.ok) throw new Error(`internal backend login failed: HTTP ${response.status}`)
  const setCookie = response.headers.get('set-cookie') || ''
  const cookie = setCookie.split(';')[0]
  if (!cookie.includes('=')) throw new Error('internal backend login did not return a session cookie')
  return cookie
}
const backendCookie = await loginBackend()

const app = express()
const server = http.createServer(app)
const websocketServer = new WebSocketServer({ noServer: true })
app.set('case sensitive routing', true)
app.disable('x-powered-by')

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin')
  next()
})
app.use('/api/auth', express.json({ limit: '4kb' }))

app.get('/api/health', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  res.json({ ok: true })
})

app.get('/api/auth/status', (req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  res.json({
    enabled: Boolean(passwordHash),
    authenticated: Boolean(passwordHash) && isAuthenticated(req),
    passwordSet: Boolean(passwordHash),
  })
})

app.post('/api/auth/setup', (req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  if (passwordHash) return res.status(409).json({ error: 'PASSWORD_ALREADY_SET' })
  const password = typeof req.body?.password === 'string' ? req.body.password : ''
  if (password.length < MIN_PASSWORD_LENGTH) {
    return res.status(400).json({
      error: 'PASSWORD_TOO_SHORT',
      message: `Password must be at least ${MIN_PASSWORD_LENGTH} characters`,
    })
  }
  passwordHash = hashPassword(password)
  setValue(SECURE_PASSWORD_HASH_KEY, passwordHash)
  setSessionCookie(req, res)
  res.json({ enabled: true, authenticated: true, passwordSet: true })
})

app.post('/api/auth/login', (req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  if (!passwordHash) return res.status(403).json({ error: 'PASSWORD_SETUP_REQUIRED' })

  const key = clientKey(req)
  const lockedFor = LOGIN_LIMITER.isLocked(key)
  if (lockedFor > 0) {
    res.setHeader('Retry-After', String(Math.ceil(lockedFor / 1000)))
    return res.status(429).json({ code: 'ACCESS_RATE_LIMITED', message: 'Too many failed login attempts' })
  }

  const password = typeof req.body?.password === 'string' ? req.body.password : ''
  if (!verifyPassword(password, passwordHash)) {
    LOGIN_LIMITER.recordFailure(key)
    clearSessionCookie(req, res)
    return res.status(401).json({
      code: 'ACCESS_PASSWORD_INVALID',
      message: 'Invalid access password',
      enabled: true,
      authenticated: false,
    })
  }

  LOGIN_LIMITER.recordSuccess(key)
  setSessionCookie(req, res)
  res.json({ enabled: true, authenticated: true })
})

app.post('/api/auth/logout', (req, res) => {
  clearSessionCookie(req, res)
  res.setHeader('Cache-Control', 'no-store')
  res.json({ enabled: Boolean(passwordHash), authenticated: false })
})

app.post('/api/auth/change-password', (req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  if (!passwordHash) return res.status(409).json({ error: 'PASSWORD_SETUP_REQUIRED' })
  if (!isAuthenticated(req)) {
    return res.status(401).json({
      code: 'ACCESS_PASSWORD_REQUIRED',
      message: 'Authenticated session required',
    })
  }

  const key = clientKey(req)
  const lockedFor = LOGIN_LIMITER.isLocked(key)
  if (lockedFor > 0) {
    res.setHeader('Retry-After', String(Math.ceil(lockedFor / 1000)))
    return res.status(429).json({ code: 'ACCESS_RATE_LIMITED', message: 'Too many failed password attempts' })
  }

  const currentPassword = typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : ''
  const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : ''
  if (!verifyPassword(currentPassword, passwordHash)) {
    LOGIN_LIMITER.recordFailure(key)
    return res.status(401).json({ code: 'ACCESS_PASSWORD_INVALID' })
  }
  if (newPassword.length < MIN_PASSWORD_LENGTH) return res.status(400).json({ error: 'PASSWORD_TOO_SHORT' })

  LOGIN_LIMITER.recordSuccess(key)
  passwordHash = hashPassword(newPassword)
  setValue(SECURE_PASSWORD_HASH_KEY, passwordHash)
  setSessionCookie(req, res)
  res.json({ ok: true, enabled: true, authenticated: true })
})

app.use((req, res, next) => {
  const normalizedPath = req.path.toLowerCase().replace(/\/{2,}/g, '/')
  if (!normalizedPath.startsWith('/api/')) return next()
  if (!passwordHash) return res.status(403).json({ error: 'PASSWORD_SETUP_REQUIRED' })
  if (!isAuthenticated(req)) {
    return res.status(401).json({
      code: 'ACCESS_PASSWORD_REQUIRED',
      message: 'Access password authentication required',
    })
  }

  if (normalizedPath.startsWith('/api/controller')) {
    const requestUrl = new URL(req.originalUrl || '/', `http://${req.headers.host || 'localhost'}`)
    if (
      req.headers['x-zashboard-target-base'] ||
      req.headers['x-zashboard-target-secret'] ||
      requestUrl.searchParams.has('targetBase') ||
      requestUrl.searchParams.has('secret')
    ) {
      return res.status(400).json({ error: 'CUSTOM_CONTROLLER_TARGET_DISABLED' })
    }
  }
  next()
})

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
])

app.use((req, res) => {
  const headers = {}
  for (const [key, value] of Object.entries(req.headers)) {
    const normalized = key.toLowerCase()
    if (
      HOP_BY_HOP.has(normalized) ||
      normalized === 'cookie' ||
      normalized.startsWith('x-zashboard-target-') ||
      value === undefined
    ) continue
    headers[key] = value
  }
  headers.cookie = backendCookie
  headers.host = `127.0.0.1:${backendPort}`

  const upstream = http.request({
    hostname: '127.0.0.1',
    port: backendPort,
    path: req.originalUrl,
    method: req.method,
    headers,
  }, (upstreamRes) => {
    res.statusCode = upstreamRes.statusCode || 502
    for (const [key, value] of Object.entries(upstreamRes.headers)) {
      const normalized = key.toLowerCase()
      if (normalized === 'set-cookie' || HOP_BY_HOP.has(normalized) || value === undefined) continue
      res.setHeader(key, value)
    }
    upstreamRes.pipe(res)
  })
  upstream.on('error', (error) => {
    if (!res.headersSent) res.status(502).json({ error: 'BACKEND_UNAVAILABLE', message: error.message })
    else res.end()
  })
  req.pipe(upstream)
})

const closeWebSocket = (socket, code = 1008, reason = 'Unauthorized') => {
  try { socket.close(code, reason) } catch {}
}
const isControllerWebSocketPath = (pathname) =>
  pathname === '/api/controller-ws' || pathname.startsWith('/api/controller-ws/')

server.on('upgrade', (request, socket, head) => {
  try {
    const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`)
    if (!isControllerWebSocketPath(url.pathname)) return socket.destroy()
    if (!passwordHash || !isAuthenticated(request)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
      return socket.destroy()
    }
    if (url.searchParams.has('targetBase') || url.searchParams.has('secret')) {
      socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n')
      return socket.destroy()
    }
    websocketServer.handleUpgrade(request, socket, head, (ws) => websocketServer.emit('connection', ws, request))
  } catch {
    socket.destroy()
  }
})

websocketServer.on('connection', (clientSocket, request) => {
  const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`)
  url.searchParams.delete('targetBase')
  url.searchParams.delete('secret')
  const upstream = new WebSocket(`ws://127.0.0.1:${backendPort}${url.pathname}${url.search}`, {
    headers: { Cookie: backendCookie },
  })

  clientSocket.on('message', (data, binary) => {
    if (upstream.readyState === WebSocket.OPEN) upstream.send(data, { binary })
  })
  upstream.on('message', (data, binary) => {
    if (clientSocket.readyState === WebSocket.OPEN) clientSocket.send(data, { binary })
  })
  clientSocket.on('close', () => closeWebSocket(upstream, 1000, 'Client closed'))
  upstream.on('close', () => closeWebSocket(clientSocket, 1000, 'Upstream closed'))
  clientSocket.on('error', () => closeWebSocket(upstream))
  upstream.on('error', () => closeWebSocket(clientSocket, 1011, 'Upstream error'))
})

await new Promise((resolve, reject) => {
  server.once('error', reject)
  server.listen(gatewayPort, gatewayHost, resolve)
})
console.log(`Open-Box security gateway listening on http://${gatewayHost}:${gatewayPort}; backend loopback port ${backendPort}`)
