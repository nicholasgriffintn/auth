import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { createAuth, type AuthSessionRecord, type AuthUser, type ExternalIdentity } from '@ngriffin_uk/auth-core'
import { signJwt } from '@ngriffin_uk/auth-jwt'

import { createAppleDirectAuth } from './direct.js'

const textEncoder = new TextEncoder()
const now = new Date('2026-07-30T12:00:00.000Z')

interface TestUser extends AuthUser {
  readonly providerSubject: string
}

describe('Apple direct authentication', () => {
  it('verifies a nonce-bound identity token and issues a core session', async () => {
    const fixture = await appleTokenFixture('raw-nonce-value-long-enough')
    const sessions: AuthSessionRecord[] = []
    let resolvedIdentity: ExternalIdentity | undefined
    const auth = createAuth<TestUser>({
      users: {
        async findById(userId) {
          return userId === 'user-1'
            ? {
                id: 'user-1',
                email: 'person@example.com',
                createdAt: now,
                providerSubject: 'apple-subject'
              }
            : null
        }
      },
      sessions: {
        async create(record) {
          sessions.push(record)
        },
        async findByTokenHash() {
          return null
        },
        async deleteByTokenHash() {}
      },
      identities: {
        async findUser() {
          return null
        },
        async resolve(identity) {
          resolvedIdentity = identity
          return {
            id: 'user-1',
            email: 'person@example.com',
            createdAt: now,
            providerSubject: identity.providerSubject
          }
        }
      },
      clock: () => now
    }).use(
      createAppleDirectAuth({
        clientIds: ['com.example.web', 'com.example.ios'],
        fetch: fixture.fetch
      })
    )

    const result = await auth.providers.apple.signIn({
      identityToken: fixture.token,
      nonce: fixture.nonce,
      name: 'Example Person'
    })

    assert.equal(result.status, 'authenticated')
    assert.equal(result.session.user.providerSubject, 'apple-subject')
    assert.equal(sessions.length, 1)
    assert.equal(resolvedIdentity?.provider, 'apple')
    assert.equal(resolvedIdentity?.emailVerified, true)
    assert.deepEqual(resolvedIdentity?.claims, {
      emailVerified: true,
      isPrivateEmail: false,
      name: 'Example Person'
    })
  })

  it('rejects a token when the initiating nonce does not match', async () => {
    const fixture = await appleTokenFixture('raw-nonce-value-long-enough')
    const auth = createAuth<TestUser>({
      users: {
        async findById() {
          return null
        }
      },
      sessions: {
        async create() {},
        async findByTokenHash() {
          return null
        },
        async deleteByTokenHash() {}
      },
      identities: {
        async findUser() {
          return null
        },
        async resolve() {
          throw new Error('Identity resolution must not run.')
        }
      },
      clock: () => now
    }).use(
      createAppleDirectAuth({
        clientIds: ['com.example.web'],
        fetch: fixture.fetch
      })
    )

    await assert.rejects(
      auth.providers.apple.signIn({
        identityToken: fixture.token,
        nonce: 'different-nonce-value-long-enough'
      }),
      (error) => error instanceof Error && error.message === 'The Apple identity token is invalid.'
    )
  })
})

async function appleTokenFixture(nonce: string) {
  const generated = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  )
  if (!('privateKey' in generated)) {
    throw new TypeError('RSA key generation did not return a key pair.')
  }
  const exportedPublicJwk = await crypto.subtle.exportKey('jwk', generated.publicKey)
  const publicJwk = {
    ...exportedPublicJwk,
    kid: 'apple-test-key',
    alg: 'RS256',
    use: 'sig'
  }
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(nonce))
  const hashedNonce = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
  const token = await signJwt(
    {
      iss: 'https://appleid.apple.com',
      aud: 'com.example.web',
      sub: 'apple-subject',
      email: 'person@example.com',
      email_verified: 'true',
      is_private_email: 'false',
      nonce: hashedNonce,
      iat: Math.floor(now.getTime() / 1_000) - 30,
      exp: Math.floor(now.getTime() / 1_000) + 300
    },
    {
      algorithm: 'RS256',
      key: generated.privateKey,
      header: { kid: 'apple-test-key' }
    }
  )
  return {
    nonce,
    token,
    fetch: async () =>
      new Response(JSON.stringify({ keys: [publicJwk] }), {
        headers: {
          'Cache-Control': 'max-age=300',
          'Content-Type': 'application/json'
        }
      })
  }
}
