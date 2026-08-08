import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { AuthError } from '@ngriffin_uk/auth-core'

import { parseWebAuthnResponse } from './client-response.js'

describe('WebAuthn client responses', () => {
  it('parses the central browser registration response', () => {
    assert.deepEqual(
      parseWebAuthnResponse(
        'registration',
        JSON.stringify({
          credentialId: 'credential-id',
          clientDataJSON: 'client-data',
          attestationObject: 'attestation',
          transports: ['internal', 'hybrid']
        })
      ),
      {
        credentialId: 'credential-id',
        clientDataJSON: 'client-data',
        attestationObject: 'attestation',
        transports: ['internal', 'hybrid']
      }
    )
  })

  it('parses the central browser authentication response', () => {
    assert.deepEqual(
      parseWebAuthnResponse('authentication', {
        credentialId: 'credential-id',
        clientDataJSON: 'client-data',
        authenticatorData: 'authenticator-data',
        signature: 'signature',
        userHandle: 'user-handle'
      }),
      {
        credentialId: 'credential-id',
        clientDataJSON: 'client-data',
        authenticatorData: 'authenticator-data',
        signature: 'signature',
        userHandle: 'user-handle'
      }
    )
  })

  it('rejects malformed responses consistently', () => {
    assert.throws(
      () => parseWebAuthnResponse('authentication', '{}'),
      (error) => error instanceof AuthError && error.code === 'invalid_input'
    )
    assert.throws(
      () =>
        parseWebAuthnResponse('registration', {
          credentialId: 'credential-id',
          clientDataJSON: 'client-data',
          attestationObject: 'attestation',
          transports: ['cable']
        }),
      (error) => error instanceof AuthError && error.code === 'invalid_input'
    )
  })
})
