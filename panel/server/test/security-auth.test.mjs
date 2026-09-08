import assert from 'node:assert/strict'
import test from 'node:test'
import { createLoginLimiter, hashPassword, verifyPassword } from '../security-auth.mjs'

test('security-auth hashes passwords without retaining plaintext', () => {
  const encoded = hashPassword('correct horse battery staple')
  assert.match(encoded, /^scrypt-v1\$/)
  assert.equal(encoded.includes('correct horse battery staple'), false)
  assert.equal(verifyPassword('correct horse battery staple', encoded), true)
  assert.equal(verifyPassword('wrong', encoded), false)
})

test('security-auth login limiter locks after repeated failures and resets after success', () => {
  const limiter = createLoginLimiter({ maxFailures: 3, windowMs: 1_000, lockMs: 5_000 })
  assert.equal(limiter.isLocked('192.0.2.1', 0), 0)
  limiter.recordFailure('192.0.2.1', 10)
  limiter.recordFailure('192.0.2.1', 20)
  assert.equal(limiter.isLocked('192.0.2.1', 30), 0)
  limiter.recordFailure('192.0.2.1', 40)
  assert.equal(limiter.isLocked('192.0.2.1', 50), 4_990)
  limiter.recordSuccess('192.0.2.1')
  assert.equal(limiter.isLocked('192.0.2.1', 60), 0)
})
