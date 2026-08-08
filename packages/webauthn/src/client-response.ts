import { AuthError, isRecord } from '@ngriffin_uk/auth-core'

import type {
  WebAuthnAuthenticationResponse,
  WebAuthnRegistrationResponse
} from './types.js'

export function parseWebAuthnResponse(
  ceremony: 'authentication',
  value: unknown
): WebAuthnAuthenticationResponse
export function parseWebAuthnResponse(
  ceremony: 'registration',
  value: unknown
): WebAuthnRegistrationResponse
export function parseWebAuthnResponse(
  ceremony: 'authentication' | 'registration',
  value: unknown
): WebAuthnAuthenticationResponse | WebAuthnRegistrationResponse {
  let response: unknown = value
  try {
    response = typeof value === 'string' ? JSON.parse(value) : value
  } catch {
    throw new AuthError('invalid_input', 'The WebAuthn response is invalid.')
  }
  if (
    !isRecord(response) ||
    typeof response.credentialId !== 'string' ||
    response.credentialId.length === 0 ||
    typeof response.clientDataJSON !== 'string' ||
    response.clientDataJSON.length === 0
  ) {
    throw new AuthError('invalid_input', 'The WebAuthn response is invalid.')
  }
  if (ceremony === 'registration') {
    if (response.transports !== undefined && !Array.isArray(response.transports)) {
      throw new AuthError('invalid_input', 'The WebAuthn response is invalid.')
    }
    for (const transport of response.transports ?? []) {
      if (
        transport !== 'ble' &&
        transport !== 'hybrid' &&
        transport !== 'internal' &&
        transport !== 'nfc' &&
        transport !== 'usb'
      ) {
        throw new AuthError('invalid_input', 'The WebAuthn response is invalid.')
      }
    }
    if (
      typeof response.attestationObject !== 'string' ||
      response.attestationObject.length === 0
    ) {
      throw new AuthError('invalid_input', 'The WebAuthn response is invalid.')
    }
    return {
      credentialId: response.credentialId,
      clientDataJSON: response.clientDataJSON,
      attestationObject: response.attestationObject,
      ...(response.transports
        ? { transports: response.transports as readonly AuthenticatorTransport[] }
        : {})
    }
  }
  if (
    typeof response.authenticatorData !== 'string' ||
    response.authenticatorData.length === 0 ||
    typeof response.signature !== 'string' ||
    response.signature.length === 0 ||
    (response.userHandle !== undefined &&
      (typeof response.userHandle !== 'string' || response.userHandle.length === 0))
  ) {
    throw new AuthError('invalid_input', 'The WebAuthn response is invalid.')
  }
  return {
    credentialId: response.credentialId,
    clientDataJSON: response.clientDataJSON,
    authenticatorData: response.authenticatorData,
    signature: response.signature,
    ...(response.userHandle ? { userHandle: response.userHandle } : {})
  }
}
