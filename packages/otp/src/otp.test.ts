import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  AuthError,
  createAuth,
  type AuthChallengeRecord,
  type AuthSessionRecord,
  type AuthUser
} from '@ngriffin_uk/auth-core'
import { decodeBase32 } from '@ngriffin_uk/auth-encoding'

import {
  generateHotp,
  getTotpStep,
  generateTotp,
  hashRecoveryCode,
  createTotpUri,
  otpAuth,
  verifyTotp,
  type OtpCredential
} from './index.js'

const textEncoder = new TextEncoder()

describe('OTP primitives', () => {
  it('uses one canonical recovery-code hash regardless of casing', async () => {
    const lower = await hashRecoveryCode('abcd-2345-efgh-6723')
    const upper = await hashRecoveryCode('ABCD-2345-EFGH-6723')

    assert.equal(lower, upper)
    assert.match(String(lower), /^[A-Za-z0-9_-]{43}$/u)
  })

  it('rejects unsafe plugin configuration before installation', () => {
    const store = {
      async saveCredential() {},
      async findCredential() {
        return null
      },
      async advanceStep() {
        return false
      },
      async consumeRecoveryCode() {
        return false
      }
    }
    assert.throws(() => otpAuth({ issuer: '', store }), /issuer/u)
    assert.throws(
      () =>
        otpAuth({
          issuer: 'Example',
          store,
          options: { digits: 5 }
        }),
      /digits/u
    )
    assert.throws(
      () =>
        otpAuth({
          issuer: 'Example',
          store,
          options: { periodSeconds: 0 }
        }),
      /period/u
    )
  })

  it('matches RFC 4226 HOTP vectors', async () => {
    const secret = textEncoder.encode('12345678901234567890')
    const expected = [
      '755224',
      '287082',
      '359152',
      '969429',
      '338314',
      '254676',
      '287922',
      '162583',
      '399871',
      '520489'
    ]
    for (const [counter, code] of expected.entries()) {
      assert.equal(await generateHotp(secret, BigInt(counter)), code)
    }
  })

  it('matches RFC 6238 and prevents accepted-step replay', async () => {
    const secret = textEncoder.encode('12345678901234567890')
    const now = new Date(59_000)
    const code = await generateTotp(secret, now, { digits: 8 })
    assert.equal(code, '94287082')
    const accepted = await verifyTotp(code, secret, now, {
      digits: 8,
      window: 0
    })
    assert.equal(accepted.valid, true)
    assert.notEqual(accepted.step, undefined)
    const acceptedStep = accepted.step
    if (acceptedStep === undefined) {
      throw new Error('Expected an accepted TOTP step.')
    }
    assert.equal(
      (
        await verifyTotp(code, secret, now, {
          digits: 8,
          window: 0,
          afterStep: acceptedStep
        })
      ).valid,
      false
    )
  })

  it('rejects malformed codes and dates before cryptographic work', async () => {
    const secret = textEncoder.encode('12345678901234567890')
    assert.deepEqual(await verifyTotp('9'.repeat(1_000_000), secret, new Date(59_000)), { valid: false })
    assert.throws(() => getTotpStep(new Date(Number.NaN)), /valid/u)
    await assert.rejects(
      Reflect.apply(verifyTotp, undefined, ['123456', secret, new Date(59_000), { afterStep: Number.NaN }]),
      /accepted step/u
    )
    assert.throws(
      () =>
        createTotpUri({
          issuer: 'i'.repeat(129),
          accountName: 'person@example.com',
          secret
        }),
      /invalid/u
    )
  })

  it('runs setup, replay-safe MFA, and one-use recovery flows', async () => {
    let now = new Date('2026-01-01T00:00:00.000Z')
    const user: AuthUser = {
      id: 'user-1',
      email: 'person@example.com',
      createdAt: now
    }
    const challenges = new Map<string, AuthChallengeRecord>()
    const sessions = new Map<string, AuthSessionRecord>()
    let credential: OtpCredential | null = null
    let recoveryHashes = new Set<string>()
    const auth = createAuth({
      users: {
        async findById(userId) {
          return userId === user.id ? user : null
        }
      },
      sessions: {
        async create(session) {
          sessions.set(session.tokenHash, session)
        },
        async findByTokenHash(tokenHash) {
          return sessions.get(tokenHash) ?? null
        },
        async deleteByTokenHash(tokenHash) {
          sessions.delete(tokenHash)
        }
      },
      challenges: {
        async create(challenge) {
          challenges.set(challenge.tokenHash, challenge)
        },
        async findByTokenHash(tokenHash) {
          return challenges.get(tokenHash) ?? null
        },
        async consumeByTokenHash(tokenHash) {
          const challenge = challenges.get(tokenHash) ?? null
          challenges.delete(tokenHash)
          return challenge
        },
        async incrementAttempts(tokenHash, expectedAttempts) {
          const challenge = challenges.get(tokenHash)
          if (!challenge || challenge.attempts !== expectedAttempts) return false
          challenges.set(tokenHash, {
            ...challenge,
            attempts: challenge.attempts + 1
          })
          return true
        }
      },
      clock: () => now,
      randomBytes: (length) => new Uint8Array(length).fill(13)
    }).use(
      otpAuth({
        issuer: 'Example',
        store: {
          async saveCredential(input) {
            credential = {
              secret: input.secret,
              lastAcceptedStep: input.lastAcceptedStep
            }
            recoveryHashes = new Set(input.recoveryCodeHashes)
          },
          async findCredential() {
            return credential
          },
          async advanceStep(_userId, step) {
            if (credential?.lastAcceptedStep !== undefined && step <= credential.lastAcceptedStep) {
              return false
            }
            if (!credential) return false
            credential = { ...credential, lastAcceptedStep: step }
            return true
          },
          async consumeRecoveryCode(_userId, codeHash) {
            return recoveryHashes.delete(codeHash)
          }
        }
      })
    )

    const mismatchedSetup = await auth.providers.otp.startSetup({
      userId: user.id,
      accountName: user.email
    })
    if (mismatchedSetup.status !== 'mfa_setup_required') {
      throw new Error('Expected MFA setup.')
    }
    const mismatchedSecret = new URL(String(mismatchedSetup.challenge.parameters?.uri)).searchParams.get('secret')
    assert.ok(mismatchedSecret)
    await assert.rejects(
      auth.providers.otp.verifySetup({
        token: mismatchedSetup.challenge.continuationToken,
        code: await generateTotp(decodeBase32(mismatchedSecret), now),
        expectedUserId: 'another-user'
      }),
      (error) => error instanceof AuthError && error.code === 'challenge_mismatch'
    )
    assert.equal(credential, null)

    const setup = await auth.providers.otp.startSetup({
      userId: user.id,
      accountName: user.email
    })
    assert.equal(setup.status, 'mfa_setup_required')
    if (setup.status !== 'mfa_setup_required') {
      throw new Error('Expected MFA setup.')
    }
    const uri = setup.challenge.parameters?.uri
    assert.equal(typeof uri, 'string')
    const secretValue = new URL(String(uri)).searchParams.get('secret')
    assert.ok(secretValue)
    const recoveryCodes = setup.challenge.parameters?.recoveryCodes
    assert.ok(Array.isArray(recoveryCodes))
    const recoveryCode = recoveryCodes[0]
    const resetRecoveryCode = recoveryCodes[1]
    assert.equal(typeof recoveryCode, 'string')
    assert.equal(typeof resetRecoveryCode, 'string')
    const secret = decodeBase32(secretValue)
    const setupCode = await generateTotp(secret, now)
    assert.equal(
      (
        await auth.providers.otp.verifySetup({
          token: setup.challenge.continuationToken,
          code: setupCode
        })
      ).status,
      'authenticated'
    )

    now = new Date(now.getTime() + 30_000)
    const challenge = await auth.providers.otp.createChallenge(user.id)
    assert.equal(challenge.status, 'mfa_challenge_required')
    if (challenge.status !== 'mfa_challenge_required') {
      throw new Error('Expected MFA challenge.')
    }
    const code = await generateTotp(secret, now)
    await assert.rejects(
      auth.providers.otp.verifyChallenge({
        token: challenge.challenge.continuationToken,
        code: 'not-a-code'
      }),
      (error) => error instanceof AuthError && error.code === 'invalid_credentials'
    )
    await auth.providers.otp.verifyChallenge({
      token: challenge.challenge.continuationToken,
      code
    })

    const replay = await auth.providers.otp.createChallenge(user.id)
    if (replay.status !== 'mfa_challenge_required') {
      throw new Error('Expected MFA challenge.')
    }
    await assert.rejects(
      auth.providers.otp.verifyChallenge({
        token: replay.challenge.continuationToken,
        code
      }),
      (error) => error instanceof AuthError && error.code === 'invalid_credentials'
    )

    const recoveryChallenge = await auth.providers.otp.createChallenge(user.id)
    if (recoveryChallenge.status !== 'mfa_challenge_required') {
      throw new Error('Expected MFA challenge.')
    }
    await assert.rejects(
      auth.providers.otp.useRecoveryCode({
        token: recoveryChallenge.challenge.continuationToken,
        code: 'not-a-code'
      }),
      (error) => error instanceof AuthError && error.code === 'invalid_credentials'
    )
    assert.equal(
      (
        await auth.providers.otp.useRecoveryCode({
          token: recoveryChallenge.challenge.continuationToken,
          code: String(recoveryCode).toUpperCase()
        })
      ).status,
      'authenticated'
    )
    const sessionCount = sessions.size
    const resetChallenge = await auth.providers.otp.createChallenge(user.id)
    if (resetChallenge.status !== 'mfa_challenge_required') {
      throw new Error('Expected MFA challenge.')
    }
    assert.equal(
      (
        await auth.providers.otp.verifyRecoveryCode({
          token: resetChallenge.challenge.continuationToken,
          code: String(resetRecoveryCode)
        })
      ).id,
      user.id
    )
    assert.equal(sessions.size, sessionCount)
    const reusedRecoveryChallenge = await auth.providers.otp.createChallenge(user.id)
    if (reusedRecoveryChallenge.status !== 'mfa_challenge_required') {
      throw new Error('Expected MFA challenge.')
    }
    await assert.rejects(
      auth.providers.otp.useRecoveryCode({
        token: reusedRecoveryChallenge.challenge.continuationToken,
        code: String(recoveryCode)
      }),
      (error) => error instanceof AuthError && error.code === 'invalid_credentials'
    )
  })
})
