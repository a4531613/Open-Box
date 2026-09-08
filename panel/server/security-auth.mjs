import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'

const SCRYPT_KEY_LENGTH = 64
const HASH_PREFIX = 'scrypt-v1'

const safeEqual = (left, right) => {
  if (!Buffer.isBuffer(left) || !Buffer.isBuffer(right) || left.length !== right.length) return false
  return timingSafeEqual(left, right)
}

export const hashPassword = (password) => {
  const salt = randomBytes(16)
  const derived = scryptSync(String(password), salt, SCRYPT_KEY_LENGTH)
  return `${HASH_PREFIX}$${salt.toString('base64url')}$${derived.toString('base64url')}`
}

export const verifyPassword = (password, encoded) => {
  if (typeof encoded !== 'string') return false
  const [prefix, saltText, hashText] = encoded.split('$')
  if (prefix !== HASH_PREFIX || !saltText || !hashText) return false

  try {
    const salt = Buffer.from(saltText, 'base64url')
    const expected = Buffer.from(hashText, 'base64url')
    const actual = scryptSync(String(password), salt, expected.length)
    return safeEqual(actual, expected)
  } catch {
    return false
  }
}

export const createLoginLimiter = ({ maxFailures = 5, windowMs = 5 * 60_000, lockMs = 15 * 60_000 } = {}) => {
  const entries = new Map()

  const keyOf = (key) => String(key || 'unknown')
  const nowState = (key, now = Date.now()) => {
    const id = keyOf(key)
    const current = entries.get(id)
    if (!current) return { id, failures: 0, windowStartedAt: now, lockedUntil: 0 }
    if (current.lockedUntil > now) return { id, ...current }
    if (now - current.windowStartedAt >= windowMs) {
      entries.delete(id)
      return { id, failures: 0, windowStartedAt: now, lockedUntil: 0 }
    }
    return { id, ...current }
  }

  return {
    isLocked(key, now = Date.now()) {
      const state = nowState(key, now)
      return state.lockedUntil > now ? state.lockedUntil - now : 0
    },
    recordFailure(key, now = Date.now()) {
      const state = nowState(key, now)
      const failures = state.failures + 1
      const lockedUntil = failures >= maxFailures ? now + lockMs : 0
      entries.set(state.id, {
        failures,
        windowStartedAt: state.windowStartedAt,
        lockedUntil,
      })
      return { failures, lockedUntil }
    },
    recordSuccess(key) {
      entries.delete(keyOf(key))
    },
  }
}
