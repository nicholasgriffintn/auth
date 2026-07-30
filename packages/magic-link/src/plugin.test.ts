import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  AuthError,
  createAuth,
  type AuthChallengeRecord,
  type AuthSessionRecord,
  type AuthUser
} from '@ngriffin_uk/auth-core'

import { magicLinkAuth } from './plugin.js'
import type { MagicLinkDelivery } from './types.js'

const user: AuthUser = {
  id: 'user-1',
  email: 'person@example.com',
  createdAt: new Date('2026-01-01T00:00:00.000Z')
}

describe('magicLinkAuth', () => {
  it('delivers and authenticates a single-use link', async () => {
    const fixture = createFixture('link')
    await fixture.auth.providers['magic-link'].request(user.email)

    assert.equal(fixture.deliveries.length, 1)
    const token = fixture.deliveries[0]?.token
    assert.ok(token)

    const result = await fixture.auth.providers['magic-link'].authenticate({
      token
    })
    assert.equal(result.status, 'authenticated')
    assert.equal(fixture.sessions.size, 1)

    await assert.rejects(
      fixture.auth.providers['magic-link'].authenticate({ token }),
      (error: unknown) => error instanceof AuthError && error.code === 'challenge_expired'
    )
  })

  it('keeps a code challenge available after an incorrect code', async () => {
    const fixture = createFixture('code')
    const requested = await fixture.auth.providers['magic-link'].request(user.email)
    assert.ok(requested && 'challenge' in requested)
    const continuationToken = requested.challenge.continuationToken
    const code = fixture.deliveries[0]?.token
    assert.ok(code)
    assert.match(code, /^\d{6}$/u)

    await assert.rejects(
      fixture.auth.providers['magic-link'].verify({
        token: continuationToken,
        code: '000000'
      }),
      (error: unknown) => error instanceof AuthError && error.code === 'invalid_credentials'
    )

    const verified = await fixture.auth.providers['magic-link'].verify({
      token: continuationToken,
      code
    })
    assert.equal(verified.id, user.id)
  })

  it('invalidates a code challenge after five incorrect attempts', async () => {
    const fixture = createFixture('code')
    const requested = await fixture.auth.providers['magic-link'].request(user.email)
    assert.ok(requested && 'challenge' in requested)
    const continuationToken = requested.challenge.continuationToken
    const issuedCode = fixture.deliveries[0]?.token
    assert.ok(issuedCode)
    const wrongCode = issuedCode === '000000' ? '111111' : '000000'

    for (let attempt = 0; attempt < 5; attempt += 1) {
      await assert.rejects(
        fixture.auth.providers['magic-link'].verify({
          token: continuationToken,
          code: wrongCode
        }),
        (error: unknown) => error instanceof AuthError && error.code === 'invalid_credentials'
      )
    }
    await assert.rejects(
      fixture.auth.providers['magic-link'].verify({
        token: continuationToken,
        code: issuedCode
      }),
      (error: unknown) => error instanceof AuthError && error.code === 'challenge_expired'
    )
  })
})

function createFixture(mode: 'code' | 'link') {
  const challenges = new Map<string, AuthChallengeRecord>()
  const sessions = new Map<string, AuthSessionRecord>()
  const deliveries: MagicLinkDelivery[] = []
  const auth = createAuth({
    users: {
      async findById(userId) {
        return userId === user.id ? user : null
      }
    },
    sessions: {
      async create(record) {
        sessions.set(record.tokenHash, record)
      },
      async findByTokenHash(tokenHash) {
        return sessions.get(tokenHash) ?? null
      },
      async deleteByTokenHash(tokenHash) {
        sessions.delete(tokenHash)
      }
    },
    challenges: {
      async create(record) {
        challenges.set(record.tokenHash, record)
      },
      async findByTokenHash(tokenHash) {
        return challenges.get(tokenHash) ?? null
      },
      async consumeByTokenHash(tokenHash) {
        const record = challenges.get(tokenHash) ?? null
        challenges.delete(tokenHash)
        return record
      },
      async incrementAttempts(tokenHash, expectedAttempts) {
        const record = challenges.get(tokenHash)
        if (!record || record.attempts !== expectedAttempts) return false
        challenges.set(tokenHash, {
          ...record,
          attempts: record.attempts + 1
        })
        return true
      }
    }
  }).use(
    magicLinkAuth({
      mode,
      async resolveUser(email) {
        return email === user.email ? user : null
      },
      async send(delivery) {
        deliveries.push(delivery)
      }
    })
  )
  return { auth, deliveries, sessions }
}
