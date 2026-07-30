import { useCallback, useEffect, useRef, useState } from 'react'

import { className, combineClassNames } from './config.js'
import { useAuth } from './context.js'
import type { ExternalAuthProvider } from './types.js'
import {
  isNonEmptyString,
  isRecord,
  optionalString
} from './value.js'

const APPLE_SCRIPT_ID = 'auth-apple-sign-in-js'
const APPLE_SCRIPT_SRC =
  'https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js'

interface AppleSignInDetail {
  readonly authorization?: {
    readonly id_token?: string
    readonly state?: string
  }
  readonly user?: {
    readonly name?: {
      readonly firstName?: string
      readonly lastName?: string
    }
  }
}

interface AppleAuth {
  init(config: {
    readonly clientId: string
    readonly scope: string
    readonly redirectURI: string
    readonly state: string
    readonly nonce: string
    readonly usePopup: boolean
  }): void
}

declare global {
  interface Window {
    AppleID?: { readonly auth: AppleAuth }
  }
}

export function AppleDirectProviderControl({
  provider
}: {
  readonly provider: ExternalAuthProvider
}) {
  const { config, state: authState, submit } = useAuth()
  const [ready, setReady] = useState(false)
  const [error, setError] = useState<string>()
  const nonce = useRef<string | undefined>(undefined)
  const state = useRef<string | undefined>(undefined)

  const initialise = useCallback(async () => {
    if (!provider.clientId) {
      setError('Sign in with Apple is not configured.')
      return
    }
    try {
      const nextNonce = randomValue()
      const nextState = randomValue()
      await loadAppleScript()
      if (!window.AppleID?.auth) {
        throw new Error('Sign in with Apple failed to load.')
      }
      window.AppleID.auth.init({
        clientId: provider.clientId,
        scope: provider.scope ?? 'name email',
        redirectURI: provider.redirectUri ?? window.location.origin,
        state: nextState,
        nonce: await sha256Hex(nextNonce),
        usePopup: true
      })
      nonce.current = nextNonce
      state.current = nextState
      setError(undefined)
      setReady(true)
    } catch (cause) {
      setError(errorMessage(cause))
    }
  }, [provider.clientId, provider.redirectUri, provider.scope])

  useEffect(() => {
    void initialise()
  }, [initialise])

  useEffect(() => {
    const success = (event: Event) => {
      const detail = readAppleSignInDetail(event)
      const identityToken = detail?.authorization?.id_token
      if (
        !identityToken ||
        !nonce.current ||
        detail.authorization?.state !== state.current
      ) {
        setError('Sign in with Apple returned invalid credentials.')
        void initialise()
        return
      }
      const fullName = [
        detail.user?.name?.firstName,
        detail.user?.name?.lastName
      ]
        .filter(isNonEmptyString)
        .join(' ')
      setReady(false)
      void submit({
        action: 'sign_in_direct',
        provider: provider.id,
        values: {
          identityToken,
          nonce: nonce.current,
          ...(fullName ? { fullName } : {})
        }
      }).finally(() => void initialise())
    }
    const failure = () => {
      setError('Sign in with Apple was cancelled.')
      void initialise()
    }
    document.addEventListener('AppleIDSignInOnSuccess', success)
    document.addEventListener('AppleIDSignInOnFailure', failure)
    return () => {
      document.removeEventListener('AppleIDSignInOnSuccess', success)
      document.removeEventListener('AppleIDSignInOnFailure', failure)
    }
  }, [initialise, provider.id, submit])

  return (
    <div data-auth-provider={provider.id}>
      {provider.separatorBefore ? (
        <div className={className(config, 'separator')}>
          {provider.separatorBefore}
        </div>
      ) : null}
      {error ? (
        <div className={className(config, 'error')} role="alert">
          {error}
        </div>
      ) : null}
      <div
        aria-disabled={!ready || authState.submitting}
        className={combineClassNames(
          className(config, 'providerButton'),
          provider.className
        )}
        style={{
          opacity: !ready || authState.submitting ? 0.6 : undefined,
          pointerEvents:
            !ready || authState.submitting ? "none" : undefined,
        }}
      >
        <div
          data-border="false"
          data-border-radius="8"
          data-color="white"
          data-height="44"
          data-type="sign-in"
          data-width="100%"
          id="appleid-signin"
        />
      </div>
    </div>
  )
}

async function loadAppleScript(): Promise<void> {
  if (window.AppleID?.auth) return
  const existing = document.getElementById(APPLE_SCRIPT_ID)
  if (existing) {
    await scriptCompletion(existing)
    return
  }
  const script = document.createElement('script')
  script.id = APPLE_SCRIPT_ID
  script.src = APPLE_SCRIPT_SRC
  script.async = true
  document.head.appendChild(script)
  await scriptCompletion(script)
}

function scriptCompletion(element: HTMLElement): Promise<void> {
  return new Promise((resolve, reject) => {
    if (window.AppleID?.auth) {
      resolve()
      return
    }
    element.addEventListener('load', () => resolve(), { once: true })
    element.addEventListener(
      'error',
      () => reject(new Error('Sign in with Apple failed to load.')),
      { once: true }
    )
  })
}

function randomValue(): string {
  return crypto.randomUUID().replace(/-/gu, '')
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(value)
  )
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, '0')
  ).join('')
}

export function readAppleSignInDetail(
  event: Event
): AppleSignInDetail | undefined {
  if (!('detail' in event) || !isRecord(event.detail)) return undefined
  const identityToken = isRecord(event.detail.authorization)
    ? optionalString(event.detail.authorization.id_token)
    : undefined
  const authorizationState = isRecord(event.detail.authorization)
    ? optionalString(event.detail.authorization.state)
    : undefined
  const authorization =
    identityToken || authorizationState
      ? {
          ...(identityToken ? { id_token: identityToken } : {}),
          ...(authorizationState ? { state: authorizationState } : {})
        }
      : undefined
  const user = isRecord(event.detail.user) ? event.detail.user : undefined
  const name = user && isRecord(user.name) ? user.name : undefined
  const firstName = name ? optionalString(name.firstName) : undefined
  const lastName = name ? optionalString(name.lastName) : undefined
  return {
    ...(authorization ? { authorization } : {}),
    ...(name
      ? {
          user: {
            name: {
              ...(firstName ? { firstName } : {}),
              ...(lastName ? { lastName } : {})
            }
          }
        }
      : {})
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : 'Sign in with Apple could not be initialised.'
}
