import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  AuthError,
  createAuth,
  isRecord,
  type AuthChallengeRecord,
  type AuthSessionRecord,
  type AuthUser,
  type ExternalIdentity
} from '@ngriffin_uk/auth-core'
import { signJwt } from '@ngriffin_uk/auth-jwt'

import { createAmazonCognitoDirectAuth } from './direct.js'
import type { CognitoTokenSet } from './direct-types.js'

const now = new Date('2026-01-01T00:00:00.000Z')
const region = 'eu-west-2'
const userPoolId = 'eu-west-2_example'
const clientId = 'client123'
const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`
const user: AuthUser = {
  id: 'user-1',
  email: 'person@example.com',
  createdAt: now
}

describe('Amazon Cognito direct authentication', () => {
  it('maps every interactive Cognito challenge to the shared flow contract', async () => {
    const cases = [
      ['EMAIL_MFA', 'mfa_challenge_required', 'email_otp'],
      ['EMAIL_OTP', 'mfa_challenge_required', 'email_otp'],
      ['SMS_MFA', 'mfa_challenge_required', 'sms_mfa'],
      ['SMS_OTP', 'mfa_challenge_required', 'sms_otp'],
      ['SOFTWARE_TOKEN_MFA', 'mfa_challenge_required', 'software_token_mfa'],
      ['MFA_SETUP', 'mfa_setup_required', 'mfa_setup'],
      ['SOFTWARE_TOKEN_SETUP', 'mfa_setup_required', 'mfa_setup'],
      ['NEW_PASSWORD_REQUIRED', 'new_password_required', 'new_password'],
      ['SELECT_CHALLENGE', 'challenge_selection_required', 'mfa_selection'],
      ['SELECT_MFA_TYPE', 'challenge_selection_required', 'mfa_selection'],
      ['CUSTOM_CHALLENGE', 'custom_challenge_required', 'custom'],
      ['PASSWORD', 'custom_challenge_required', 'password'],
      ['WEB_AUTHN', 'webauthn_challenge_required', 'webauthn'],
      ['PASSWORD_VERIFIER', 'unsupported_challenge', 'unsupported'],
      ['DEVICE_SRP_AUTH', 'unsupported_challenge', 'unsupported']
    ] as const

    for (const [challengeName, status, kind] of cases) {
      const fixture = createFixture(async (operation) => {
        assert.equal(operation, 'InitiateAuth')
        return json({
          ChallengeName: challengeName,
          ChallengeParameters: { delivery: 'masked', SRP_B: 'not-forwarded' },
          AvailableChallenges: ['PASSWORD', 'WEB_AUTHN'],
          Session: 'upstream-session-value-12345'
        })
      })
      const result = await fixture.auth.providers['amazon-cognito'].startSignIn({
        username: user.email
      })
      assert.equal(result.status, status)
      assert.equal(result.challenge.kind, kind)
      assert.equal(JSON.stringify(result).includes('upstream-session-value'), false)
      assert.equal(JSON.stringify(result).includes('not-forwarded'), false)
    }
  })

  it('chains code challenges and adds username and client secret hash', async () => {
    const requests: Array<{
      readonly operation: string
      readonly body: Readonly<Record<string, unknown>>
    }> = []
    const fixture = createFixture(
      async (operation, body) => {
        requests.push({ operation, body })
        if (operation === 'InitiateAuth') {
          return json({
            ChallengeName: 'EMAIL_OTP',
            Session: 'upstream-session-value-12345'
          })
        }
        return json({
          ChallengeName: 'WEB_AUTHN',
          ChallengeParameters: {
            CREDENTIAL_REQUEST_OPTIONS: '{"challenge":"provider-value"}'
          },
          Session: 'next-upstream-session-value'
        })
      },
      { clientSecret: 'client-secret' }
    )

    const first = await fixture.auth.providers['amazon-cognito'].startSignIn({
      username: user.email
    })
    if (first.status !== 'mfa_challenge_required') {
      assert.fail('Expected an email-code challenge.')
    }
    const second = await fixture.auth.providers['amazon-cognito'].respondToCode({
      token: first.challenge.continuationToken,
      code: '123456'
    })

    assert.equal(second.status, 'webauthn_challenge_required')
    const responseBody = record(requests[1]?.body['ChallengeResponses'])
    assert.equal(responseBody['USERNAME'], user.email)
    assert.equal(responseBody['EMAIL_OTP_CODE'], '123456')
    assert.equal(typeof responseBody['SECRET_HASH'], 'string')
  })

  it('keeps an interactive challenge available after Cognito rejects a code', async () => {
    let attempts = 0
    const fixture = createFixture(async (operation) => {
      if (operation === 'InitiateAuth') {
        return json({
          ChallengeName: 'EMAIL_OTP',
          Session: 'upstream-session-value-12345'
        })
      }
      attempts += 1
      if (attempts === 1) {
        return json({ __type: 'CodeMismatchException', message: 'Incorrect code.' }, 400)
      }
      return json({
        ChallengeName: 'SMS_MFA',
        Session: 'next-upstream-session-value'
      })
    })
    const provider = fixture.auth.providers['amazon-cognito']
    const initial = await provider.startSignIn({ username: user.email })
    if (initial.status !== 'mfa_challenge_required') {
      assert.fail('Expected an email-code challenge.')
    }

    await assert.rejects(
      provider.respondToCode({
        token: initial.challenge.continuationToken,
        code: '111111'
      }),
      (error) => error instanceof AuthError && error.code === 'invalid_credentials'
    )
    const retried = await provider.respondToCode({
      token: initial.challenge.continuationToken,
      code: '222222'
    })

    assert.equal(retried.status, 'mfa_challenge_required')
    assert.equal(retried.challenge.kind, 'sms_mfa')
  })

  it('verifies Cognito access and ID tokens before resolving identity', async () => {
    const keys = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: Uint8Array.of(1, 0, 1),
        hash: 'SHA-256'
      },
      true,
      ['sign', 'verify']
    )
    const accessToken = await signJwt(
      {
        sub: 'cognito-subject',
        iss: issuer,
        exp: now.getTime() / 1000 + 3600,
        iat: now.getTime() / 1000,
        client_id: clientId,
        token_use: 'access'
      },
      {
        algorithm: 'RS256',
        key: keys.privateKey,
        header: { kid: 'key-1' }
      }
    )
    const idToken = await signJwt(
      {
        sub: 'cognito-subject',
        iss: issuer,
        aud: clientId,
        exp: now.getTime() / 1000 + 3600,
        iat: now.getTime() / 1000,
        token_use: 'id',
        email: user.email,
        email_verified: true
      },
      {
        algorithm: 'RS256',
        key: keys.privateKey,
        header: { kid: 'key-1' }
      }
    )
    const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey)
    let observedIdentity: ExternalIdentity | undefined
    let observedTokens: CognitoTokenSet | undefined
    const fixture = createFixture(
      async (operation) => {
        assert.equal(operation, 'InitiateAuth')
        return json({
          AuthenticationResult: {
            AccessToken: accessToken,
            IdToken: idToken,
            RefreshToken: 'refresh-token',
            ExpiresIn: 3600,
            TokenType: 'Bearer'
          }
        })
      },
      {
        async jwks() {
          return json({
            keys: [{ ...jwk, kid: 'key-1', alg: 'RS256', use: 'sig' }]
          })
        },
        async resolveIdentity(identity) {
          observedIdentity = identity
          return user
        },
        async onTokens(input) {
          observedTokens = input.tokens
        }
      }
    )

    const result = await fixture.auth.providers['amazon-cognito'].signInPassword({
      username: user.email,
      password: 'correct horse battery staple'
    })

    assert.equal(result.status, 'authenticated')
    assert.equal(observedIdentity?.providerSubject, 'cognito-subject')
    assert.equal(observedIdentity?.emailVerified, true)
    assert.equal(observedTokens?.refreshToken, 'refresh-token')
    assert.equal(fixture.sessions.size, 1)

    const accessWithoutIssuedAt = await signJwt(
      {
        sub: 'cognito-subject',
        iss: issuer,
        exp: now.getTime() / 1000 + 3600,
        client_id: clientId,
        token_use: 'access'
      },
      {
        algorithm: 'RS256',
        key: keys.privateKey,
        header: { kid: 'key-1' }
      }
    )
    const invalidFixture = createFixture(
      async () =>
        json({
          AuthenticationResult: {
            AccessToken: accessWithoutIssuedAt,
            ExpiresIn: 3600,
            TokenType: 'Bearer'
          }
        }),
      {
        async jwks() {
          return json({
            keys: [{ ...jwk, kid: 'key-1', alg: 'RS256', use: 'sig' }]
          })
        }
      }
    )
    await assert.rejects(
      invalidFixture.auth.providers['amazon-cognito'].signInPassword({
        username: user.email,
        password: 'correct horse battery staple'
      }),
      (error) => error instanceof AuthError && error.code === 'provider_error'
    )
  })

  it('completes software-token setup with backend-only Cognito sessions', async () => {
    const operations: string[] = []
    const fixture = createFixture(async (operation) => {
      operations.push(operation)
      switch (operation) {
        case 'InitiateAuth':
          return json({
            ChallengeName: 'MFA_SETUP',
            Session: 'initial-upstream-session'
          })
        case 'AssociateSoftwareToken':
          return json({
            SecretCode: 'JBSWY3DPEHPK3PXP',
            Session: 'associated-upstream-session'
          })
        case 'VerifySoftwareToken':
          return json({ Session: 'verified-upstream-session' })
        case 'RespondToAuthChallenge':
          return json({
            ChallengeName: 'SOFTWARE_TOKEN_MFA',
            Session: 'final-upstream-session'
          })
        default:
          assert.fail(`Unexpected operation: ${operation}`)
      }
    })
    const initial = await fixture.auth.providers['amazon-cognito'].startSignIn({
      username: user.email
    })
    if (initial.status !== 'mfa_setup_required') {
      assert.fail('Expected MFA setup.')
    }
    await assert.rejects(
      fixture.auth.providers['amazon-cognito'].startMfaSetup({
        token: initial.challenge.continuationToken,
        accountName: user.email,
        issuer: ' '
      }),
      (error) => error instanceof AuthError && error.code === 'invalid_input'
    )
    const setup = await fixture.auth.providers['amazon-cognito'].startMfaSetup({
      token: initial.challenge.continuationToken,
      accountName: user.email,
      issuer: 'Example'
    })
    if (setup.status !== 'mfa_setup_required') {
      assert.fail('Expected MFA setup verification.')
    }
    assert.match(String(setup.challenge.parameters?.['uri']), /^otpauth:/u)
    const verified = await fixture.auth.providers['amazon-cognito'].verifyMfaSetup({
      token: setup.challenge.continuationToken,
      code: '123456'
    })

    assert.equal(verified.status, 'mfa_challenge_required')
    assert.deepEqual(operations, [
      'InitiateAuth',
      'AssociateSoftwareToken',
      'VerifySoftwareToken',
      'RespondToAuthChallenge'
    ])
    assert.equal(JSON.stringify(verified).includes('upstream-session'), false)
  })

  it('supports sign-up confirmation, recovery, password change, and revocation', async () => {
    const requests: Array<{
      readonly operation: string
      readonly body: Readonly<Record<string, unknown>>
    }> = []
    const fixture = createFixture(async (operation, body) => {
      requests.push({ operation, body })
      if (operation === 'SignUp') {
        return json({
          UserSub: 'new-cognito-subject',
          UserConfirmed: false,
          CodeDeliveryDetails: {
            DeliveryMedium: 'EMAIL',
            Destination: 'p***@example.com'
          }
        })
      }
      if (operation === 'ForgotPassword') {
        return json({
          CodeDeliveryDetails: {
            DeliveryMedium: 'EMAIL',
            Destination: 'p***@example.com'
          }
        })
      }
      return json({})
    })
    const provider = fixture.auth.providers['amazon-cognito']
    const signUp = await provider.signUp({
      username: user.email,
      password: 'correct horse battery staple',
      attributes: { email: user.email }
    })
    if (signUp.status !== 'email_verification_required') {
      assert.fail('Expected email verification.')
    }
    await provider.confirmSignUp({
      token: signUp.challenge.continuationToken,
      code: '123456'
    })
    await provider.resendConfirmationCode(user.email)
    const reset = await provider.forgotPassword(user.email)
    if (reset.status !== 'password_reset_required') {
      assert.fail('Expected password reset.')
    }
    await provider.confirmForgotPassword({
      token: reset.challenge.continuationToken,
      code: '654321',
      newPassword: 'a newer correct horse battery staple'
    })
    await provider.changePassword({
      accessToken: 'access-token',
      currentPassword: 'correct horse battery staple',
      newPassword: 'a newer correct horse battery staple'
    })
    await provider.revokeRefreshToken('refresh-token')
    await provider.signOut('access-token')

    assert.deepEqual(
      requests.map((request) => request.operation),
      [
        'SignUp',
        'ConfirmSignUp',
        'ResendConfirmationCode',
        'ForgotPassword',
        'ConfirmForgotPassword',
        'ChangePassword',
        'RevokeToken',
        'GlobalSignOut'
      ]
    )
    assert.equal(record(requests[0]?.body)['UserPoolId'], undefined)
  })

  it('returns typed recovery and confirmation flows for Cognito sign-in errors', async () => {
    for (const [type, expectedStatus] of [
      ['PasswordResetRequiredException', 'password_reset_required'],
      ['UserNotConfirmedException', 'email_verification_required']
    ] as const) {
      const fixture = createFixture(async () => json({ __type: type, message: 'provider detail' }, 400))
      const result = await fixture.auth.providers['amazon-cognito'].signInPassword({
        username: user.email,
        password: 'correct horse battery staple'
      })
      assert.equal(result.status, expectedStatus)
      assert.equal(JSON.stringify(result).includes('provider detail'), false)
    }
  })

  it('rejects malformed runtime inputs and provider token metadata', async () => {
    let requests = 0
    const fixture = createFixture(async () => {
      requests += 1
      return json({})
    })
    const provider = fixture.auth.providers['amazon-cognito']

    await assert.rejects(
      Reflect.apply(provider.signInPassword, provider, [
        {
          username: 42,
          password: 'correct horse battery staple'
        }
      ]),
      (error) => error instanceof AuthError && error.code === 'invalid_input'
    )
    await assert.rejects(
      Reflect.apply(provider.signUp, provider, [
        {
          username: user.email,
          password: 'correct horse battery staple',
          attributes: { email: 42 }
        }
      ]),
      (error) => error instanceof AuthError && error.code === 'invalid_input'
    )
    assert.equal(requests, 0)

    const invalidProvider = createFixture(async () =>
      json({
        AuthenticationResult: {
          AccessToken: 'not-reached',
          ExpiresIn: '3600'
        }
      })
    )
    await assert.rejects(
      invalidProvider.auth.providers['amazon-cognito'].signInPassword({
        username: user.email,
        password: 'correct horse battery staple'
      }),
      (error) => error instanceof AuthError && error.code === 'provider_error'
    )
  })
})

interface FixtureOptions {
  readonly clientSecret?: string
  readonly jwks?: () => Promise<Response>
  readonly resolveIdentity?: (identity: ExternalIdentity) => Promise<AuthUser>
  readonly onTokens?: (input: {
    readonly user: AuthUser
    readonly tokens: CognitoTokenSet
    readonly identity: ExternalIdentity
  }) => Promise<void>
}

function createFixture(
  responder: (operation: string, body: Readonly<Record<string, unknown>>) => Promise<Response>,
  options: FixtureOptions = {}
) {
  const challenges = new Map<string, AuthChallengeRecord>()
  const sessions = new Map<string, AuthSessionRecord>()
  const fetch: typeof globalThis.fetch = async (_input, init) => {
    const target = new Headers(init?.headers).get('X-Amz-Target')
    if (!target) {
      if (!options.jwks) return json({}, 404)
      return options.jwks()
    }
    const operation = target.split('.').at(-1)
    if (!operation) throw new Error('Missing Cognito operation.')
    return responder(operation, parseBody(init?.body))
  }
  const base = createAuth({
    users: {
      async findById(userId) {
        return userId === user.id ? user : null
      }
    },
    identities: {
      async findUser() {
        return null
      },
      async resolve(identity) {
        return options.resolveIdentity?.(identity) ?? user
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
      }
    },
    clock: () => now
  })
  const auth = base.use(
    createAmazonCognitoDirectAuth({
      region,
      userPoolId,
      clientId,
      ...(options.clientSecret ? { clientSecret: options.clientSecret } : {}),
      fetch,
      ...(options.onTokens ? { onTokens: options.onTokens } : {})
    })
  )
  return { auth, challenges, sessions }
}

function parseBody(body: BodyInit | null | undefined): Readonly<Record<string, unknown>> {
  if (typeof body !== 'string') throw new Error('Expected a JSON request.')
  return record(JSON.parse(body))
}

function record(value: unknown): Readonly<Record<string, unknown>> {
  if (!isRecord(value)) {
    throw new Error('Expected an object.')
  }
  return value
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' }
  })
}
