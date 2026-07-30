import {
  AuthError,
  normaliseEmailInput,
  type AuthFlowResult,
  type AuthPlugin,
  type AuthPluginContext,
  type AuthUser
} from '@ngriffin_uk/auth-core'
import { randomBytes } from '@ngriffin_uk/auth-crypto'

import type { MagicLinkOperations, MagicLinkPluginConfig } from './types.js'

const PROVIDER = 'magic-link'
const DEFAULT_CODE_LENGTH = 6

export function magicLinkAuth<User extends AuthUser>(
  config: MagicLinkPluginConfig<User>
): AuthPlugin<'magic-link', MagicLinkOperations<User>, User> {
  validateConfig(config)
  return {
    name: PROVIDER,
    install(context) {
      return {
        request: (email) => request(context, config, email),
        verify: (input) => verify(context, config, input),
        authenticate: async (input) => {
          const user = await verify(context, config, input)
          const issued = await context.issueSession(user.id)
          return {
            status: 'authenticated',
            session: {
              user,
              token: issued.token,
              expiresAt: issued.expiresAt
            }
          }
        }
      }
    }
  }
}

async function request<User extends AuthUser>(
  context: AuthPluginContext<User>,
  config: MagicLinkPluginConfig<User>,
  input: string
): Promise<AuthFlowResult<User> | void> {
  const email = normaliseEmailInput(input, config.normaliseEmail)
  const mode = config.mode ?? 'link'
  if (mode === 'link') {
    const issued = await context.issueChallenge(PROVIDER, 'email_verification', { email, mode })
    await config.send({
      email,
      mode,
      token: issued.token,
      expiresAt: issued.expiresAt
    })
    return
  }

  const code = secureNumericCode(config.codeLength ?? DEFAULT_CODE_LENGTH)
  const issued = await context.issueChallenge(PROVIDER, 'email_otp', {
    email,
    mode,
    codeHash: await context.hashSecret(code)
  })
  await config.send({
    email,
    mode,
    token: code,
    expiresAt: issued.expiresAt
  })
  return {
    status: 'mfa_challenge_required',
    challenge: {
      kind: 'email_otp',
      continuationToken: issued.token,
      expiresAt: issued.expiresAt
    }
  }
}

async function verify<User extends AuthUser>(
  context: AuthPluginContext<User>,
  config: MagicLinkPluginConfig<User>,
  input: { readonly token: string; readonly code?: string }
): Promise<User> {
  const mode = config.mode ?? 'link'
  const challenge =
    mode === 'code'
      ? await verifyCode(context, input)
      : await context.consumeChallenge(input.token, PROVIDER, ['email_verification'])
  if (challenge.payload['mode'] !== mode) {
    throw new AuthError('challenge_mismatch')
  }
  const email = payloadString(challenge.payload, 'email')
  const user = await config.resolveUser(email)
  if (!user || normaliseEmailInput(user.email, config.normaliseEmail) !== email) {
    throw new AuthError('invalid_credentials')
  }
  return user
}

async function verifyCode<User extends AuthUser>(
  context: AuthPluginContext<User>,
  input: { readonly token: string; readonly code?: string }
) {
  if (typeof input.code !== 'string' || input.code.length === 0 || input.code.length > 32) {
    throw new AuthError('invalid_credentials')
  }
  const challenge = await context.readChallenge(input.token, PROVIDER, ['email_otp'])
  const expected = payloadString(challenge.payload, 'codeHash')
  const actual = await context.hashSecret(input.code)
  if (!constantStringEqual(actual, expected)) {
    await context.recordChallengeFailure(input.token)
    throw new AuthError('invalid_credentials', 'The verification code is invalid.')
  }
  return context.consumeChallenge(input.token, PROVIDER, ['email_otp'])
}

function secureNumericCode(length: number): string {
  let output = ''
  while (output.length < length) {
    for (const value of randomBytes(32)) {
      if (value < 250) output += String(value % 10)
      if (output.length === length) break
    }
  }
  return output
}

function constantStringEqual(actual: string, expected: string): boolean {
  if (actual.length !== expected.length) return false
  let difference = 0
  for (let index = 0; index < actual.length; index += 1) {
    difference |= actual.charCodeAt(index) ^ expected.charCodeAt(index)
  }
  return difference === 0
}

function payloadString(payload: Readonly<Record<string, unknown>>, field: string): string {
  const value = payload[field]
  if (typeof value !== 'string') throw new AuthError('challenge_mismatch')
  return value
}

function validateConfig<User extends AuthUser>(config: MagicLinkPluginConfig<User>): void {
  const length = config.codeLength ?? DEFAULT_CODE_LENGTH
  if (config.mode !== undefined && config.mode !== 'code' && config.mode !== 'link') {
    throw new TypeError('Magic-link delivery mode is invalid.')
  }
  if (!Number.isSafeInteger(length) || length < 6 || length > 12) {
    throw new TypeError('Magic-link code length must be between 6 and 12.')
  }
}
