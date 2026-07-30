import type { AuthPlugin, AuthUser } from '@ngriffin_uk/auth-core'
import {
  createOAuthProvider,
  defineOAuthProvider,
  type OAuthOperations,
  type OAuthProviderPluginOptions
} from '@ngriffin_uk/auth-oauth2'
import { signJwt } from '@ngriffin_uk/auth-jwt'

export * from './direct.js'
export * from './direct-types.js'

export const appleDefinition = defineOAuthProvider({
  name: 'apple',
  authorizationEndpoint: 'https://appleid.apple.com/auth/authorize',
  tokenEndpoint: 'https://appleid.apple.com/auth/token',
  pkce: false,
  clientAuthentication: 'body'
})

export interface AppleOptions<User extends AuthUser>
  extends Omit<OAuthProviderPluginOptions<User>, 'clientAuthentication' | 'clientSecret'> {
  readonly teamId: string
  readonly keyId: string
  readonly privateKey: CryptoKey
  readonly clock?: () => Date
}

export function createAppleAuth<User extends AuthUser>(
  options: AppleOptions<User>
): AuthPlugin<'apple', OAuthOperations<User>, User> {
  validateIdentifier(options.teamId, 'Apple team ID')
  validateIdentifier(options.keyId, 'Apple key ID')
  const { teamId, keyId, privateKey, clock, ...oauthOptions } = options
  return createOAuthProvider(appleDefinition, {
    ...oauthOptions,
    clientAuthentication: 'body',
    clientSecret: async () => {
      const timestamp = (clock?.() ?? new Date()).getTime()
      if (!Number.isFinite(timestamp)) {
        throw new TypeError('Apple client-secret clock is invalid.')
      }
      const issuedAt = Math.floor(timestamp / 1_000)
      return signJwt(
        {
          iss: teamId,
          sub: options.clientId,
          aud: 'https://appleid.apple.com',
          iat: issuedAt,
          exp: issuedAt + 180 * 24 * 60 * 60
        },
        {
          algorithm: 'ES256',
          key: privateKey,
          header: { kid: keyId }
        }
      )
    }
  })
}

function validateIdentifier(value: string, label: string): void {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128 || !/^[A-Za-z0-9._-]+$/u.test(value)) {
    throw new TypeError(`${label} is invalid.`)
  }
}

export function importApplePrivateKey(pkcs8: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'pkcs8',
    Uint8Array.from(pkcs8).buffer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  )
}
