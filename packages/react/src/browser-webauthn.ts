import type { AuthClientChallenge } from './types.js'

export async function resolveBrowserWebAuthn(
  challenge: AuthClientChallenge
): Promise<Readonly<Record<string, string>>> {
  if (!isWebAuthnSupported()) {
    throw new Error('Passkeys are not supported on this device.')
  }
  const ceremony = requiredParameter(challenge, 'ceremony')
  const credential =
    ceremony === 'registration'
      ? await createCredential(challenge)
      : await getCredential(challenge)
  return { credential: JSON.stringify(credential) }
}

export function isWebAuthnSupported(): boolean {
  return (
    typeof globalThis.PublicKeyCredential === 'function' &&
    typeof globalThis.navigator?.credentials !== 'undefined'
  )
}

async function createCredential(challenge: AuthClientChallenge) {
  const algorithms = stringArrayParameter(challenge, 'algorithms') ?? [
    'ES256',
    'RS256'
  ]
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: decodeBase64Url(requiredParameter(challenge, 'challenge')),
    rp: {
      id: requiredParameter(challenge, 'rpId'),
      name: requiredParameter(challenge, 'rpName')
    },
    user: {
      id: decodeBase64Url(requiredParameter(challenge, 'userId')),
      name: requiredParameter(challenge, 'userName'),
      displayName: requiredParameter(challenge, 'displayName')
    },
    pubKeyCredParams: algorithms.map((algorithm) => ({
      type: 'public-key',
      alg: algorithm === 'RS256' ? -257 : -7
    })),
    timeout: positiveNumberParameter(challenge, 'timeout'),
    attestation: attestationParameter(challenge),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred'
    }
  }
  const credential = await navigator.credentials.create({ publicKey })
  if (!isPublicKeyCredential(credential)) {
    throw new Error('Passkey setup did not return a credential.')
  }
  const response = credential.response
  if (
    !('attestationObject' in response) ||
    !(response.attestationObject instanceof ArrayBuffer)
  ) {
    throw new Error('Passkey setup response is incomplete.')
  }
  return {
    credentialId: credential.id,
    clientDataJSON: encodeBase64Url(response.clientDataJSON),
    attestationObject: encodeBase64Url(response.attestationObject),
    ...('getTransports' in response &&
    typeof response.getTransports === 'function'
      ? { transports: response.getTransports() }
      : {})
  }
}

async function getCredential(challenge: AuthClientChallenge) {
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: decodeBase64Url(requiredParameter(challenge, 'challenge')),
    rpId: requiredParameter(challenge, 'rpId'),
    timeout: positiveNumberParameter(challenge, 'timeout'),
    userVerification: userVerificationParameter(challenge),
    allowCredentials: (stringArrayParameter(
      challenge,
      'allowCredentialIds'
    ) ?? []).map((id) => ({
      type: 'public-key',
      id: decodeBase64Url(id)
    }))
  }
  const credential = await navigator.credentials.get({ publicKey })
  if (!isPublicKeyCredential(credential)) {
    throw new Error('Passkey verification did not return a credential.')
  }
  const response = credential.response
  if (
    !('authenticatorData' in response) ||
    !(response.authenticatorData instanceof ArrayBuffer) ||
    !('signature' in response) ||
    !(response.signature instanceof ArrayBuffer) ||
    !('userHandle' in response)
  ) {
    throw new Error('Passkey verification response is incomplete.')
  }
  return {
    credentialId: credential.id,
    clientDataJSON: encodeBase64Url(response.clientDataJSON),
    authenticatorData: encodeBase64Url(response.authenticatorData),
    signature: encodeBase64Url(response.signature),
    ...(response.userHandle instanceof ArrayBuffer
      ? { userHandle: encodeBase64Url(response.userHandle) }
      : {})
  }
}

function isPublicKeyCredential(
  value: Credential | null
): value is PublicKeyCredential {
  return (
    value !== null &&
    typeof value.id === 'string' &&
    'response' in value &&
    isAuthenticatorResponse(value.response)
  )
}

function isAuthenticatorResponse(
  value: unknown
): value is AuthenticatorResponse {
  return (
    typeof value === 'object' &&
    value !== null &&
    'clientDataJSON' in value &&
    value.clientDataJSON instanceof ArrayBuffer
  )
}

function requiredParameter(
  challenge: AuthClientChallenge,
  name: string
): string {
  const value = challenge.parameters?.[name]
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Authentication challenge ${name} is missing.`)
  }
  return value
}

function stringArrayParameter(
  challenge: AuthClientChallenge,
  name: string
): readonly string[] | undefined {
  const value = challenge.parameters?.[name]
  if (value === undefined) return undefined
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new Error(`Authentication challenge ${name} is invalid.`)
  }
  return value
}

function positiveNumberParameter(
  challenge: AuthClientChallenge,
  name: string
): number {
  const value = Number(requiredParameter(challenge, name))
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`Authentication challenge ${name} is invalid.`)
  }
  return value
}

function attestationParameter(
  challenge: AuthClientChallenge
): AttestationConveyancePreference {
  const value = challenge.parameters?.attestation
  return value === 'direct' ? 'direct' : 'none'
}

function userVerificationParameter(
  challenge: AuthClientChallenge
): UserVerificationRequirement {
  const value = challenge.parameters?.userVerification
  if (value === 'required' || value === 'discouraged') return value
  return 'preferred'
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')
  const binary = atob(padded)
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/u, '')
}
