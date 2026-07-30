import {
  AuthError,
  type AuthFlowResult,
  type AuthPlugin,
  type AuthPluginContext,
  type AuthUser,
  type ExternalIdentity
} from '@ngriffin_uk/auth-core'
import { createRemoteJwksResolver, verifyJwt, type JwtClaims } from '@ngriffin_uk/auth-jwt'

import type { AppleDirectOperations, AppleDirectOptions, AppleDirectSignInInput } from './direct-types.js'

const PROVIDER = 'apple'
const APPLE_ISSUER = 'https://appleid.apple.com'
const APPLE_JWKS_URL = 'https://appleid.apple.com/auth/keys'
const textEncoder = new TextEncoder()

export function createAppleDirectAuth<User extends AuthUser>(
  config: AppleDirectOptions
): AuthPlugin<'apple', AppleDirectOperations<User>, User> {
  const clientIds = validateClientIds(config.clientIds)
  return {
    name: PROVIDER,
    install(context) {
      const key = createRemoteJwksResolver({
        url: APPLE_JWKS_URL,
        ...(config.fetch ? { fetch: config.fetch } : {}),
        clock: context.now
      })
      return {
        signIn: (input) => signIn(context, clientIds, key, input)
      }
    }
  }
}

async function signIn<User extends AuthUser>(
  context: AuthPluginContext<User>,
  clientIds: readonly string[],
  key: ReturnType<typeof createRemoteJwksResolver>,
  input: AppleDirectSignInInput
): Promise<AuthFlowResult<User>> {
  validateNonce(input.nonce)
  let claims: JwtClaims
  try {
    claims = await verifyJwt(input.identityToken, {
      algorithms: ['RS256'],
      key,
      issuer: APPLE_ISSUER,
      audience: clientIds,
      clock: context.now
    })
    await verifyNonce(claims['nonce'], input.nonce)
  } catch (cause) {
    throw new AuthError('invalid_credentials', 'The Apple identity token is invalid.', { cause })
  }
  const identity = toIdentity(claims, input.name)
  if (!context.identities) {
    throw new AuthError('unsupported_operation', 'An identity store is required for Apple authentication.')
  }
  const user = await context.identities.resolve(identity)
  const session = await context.issueSession(user.id)
  return {
    status: 'authenticated',
    session: {
      user,
      token: session.token,
      expiresAt: session.expiresAt
    }
  }
}

function toIdentity(claims: JwtClaims, name: string | undefined): ExternalIdentity {
  const subject = requireSubject(claims)
  const email = typeof claims['email'] === 'string' ? claims['email'] : undefined
  const emailVerified = appleBoolean(claims['email_verified'])
  return {
    provider: PROVIDER,
    providerSubject: subject,
    ...(email ? { email } : {}),
    emailVerified,
    claims: {
      emailVerified,
      isPrivateEmail: appleBoolean(claims['is_private_email']),
      ...(name ? { name } : {})
    }
  }
}

function validateClientIds(values: readonly string[]): readonly string[] {
  if (
    !Array.isArray(values) ||
    values.length === 0 ||
    values.length > 20 ||
    values.some((value) => typeof value !== 'string' || value.length === 0 || value.length > 255)
  ) {
    throw new TypeError('Apple client IDs are invalid.')
  }
  return Object.freeze([...new Set(values)])
}

function validateNonce(value: string): void {
  if (typeof value !== 'string' || value.length < 16 || value.length > 1_024) {
    throw new AuthError('invalid_input', 'Apple nonce is invalid.')
  }
}

async function verifyNonce(claim: unknown, rawNonce: string): Promise<void> {
  if (typeof claim !== 'string') {
    throw new TypeError('Apple identity token nonce is missing.')
  }
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(rawNonce))
  const hashedNonce = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
  if (claim !== hashedNonce) {
    throw new TypeError('Apple identity token nonce is invalid.')
  }
}

function requireSubject(claims: JwtClaims): string {
  if (typeof claims.sub !== 'string' || claims.sub.length === 0 || claims.sub.length > 1_024) {
    throw new TypeError('Apple identity token subject is invalid.')
  }
  return claims.sub
}

function appleBoolean(value: unknown): boolean {
  return value === true || value === 'true'
}
