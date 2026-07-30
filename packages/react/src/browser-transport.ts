import type {
  AuthClientChallenge,
  AuthClientResult,
  AuthTransport
} from './types.js'
import { isRecord } from './value.js'

export interface BrowserAuthTransportOptions {
  readonly endpoint?: string
  readonly request?: typeof fetch
  readonly credentials?: RequestCredentials
}

export function createBrowserAuthTransport<User = unknown>(
  options: BrowserAuthTransportOptions = {}
): AuthTransport<User> {
  const endpoint = options.endpoint ?? '/api/auth'
  const request = options.request ?? globalThis.fetch
  return {
    async execute(authRequest) {
      const response = await request(endpoint, {
        body: JSON.stringify(authRequest),
        credentials: options.credentials ?? 'include',
        headers: { 'Content-Type': 'application/json' },
        method: 'POST'
      })
      if (!response.ok) {
        throw new Error(await responseErrorMessage(response))
      }
      const result: unknown = await response.json()
      if (!isAuthClientResult<User>(result)) {
        throw new Error('The authentication service returned an invalid response.')
      }
      return result
    }
  }
}

async function responseErrorMessage(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json()
    if (isRecord(body)) {
      const message = body.message ?? body.error
      if (typeof message === 'string' && message.length > 0) return message
    }
  } catch {
    // Use one safe error when the service did not return JSON.
  }
  return 'Authentication could not be completed.'
}

export function followBrowserAuthRedirect(url: string): void {
  const target = new URL(url, globalThis.location.href)
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    throw new Error('The authentication service returned an invalid redirect.')
  }
  globalThis.location.assign(target.toString())
}

function isAuthClientResult<User>(value: unknown): value is AuthClientResult<User> {
  if (!isRecord(value) || typeof value.status !== 'string') return false
  switch (value.status) {
    case 'authenticated':
      return (
        value.recoveryCodes === undefined ||
        (Array.isArray(value.recoveryCodes) &&
          value.recoveryCodes.every((code) => typeof code === 'string'))
      )
    case 'completed':
      return true
    case 'redirect_required':
      return typeof value.provider === 'string' && typeof value.url === 'string'
    case 'challenge_selection_required':
    case 'custom_challenge_required':
    case 'email_verification_required':
    case 'mfa_challenge_required':
    case 'mfa_setup_required':
    case 'new_password_required':
    case 'password_reset_required':
    case 'unsupported_challenge':
    case 'webauthn_challenge_required':
      return isAuthClientChallenge(value.challenge)
    default:
      return false
  }
}

function isAuthClientChallenge(value: unknown): value is AuthClientChallenge {
  return (
    isRecord(value) &&
    typeof value.kind === 'string' &&
    typeof value.continuationToken === 'string' &&
    typeof value.expiresAt === 'string'
  )
}
