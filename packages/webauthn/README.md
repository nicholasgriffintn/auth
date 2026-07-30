# `@ngriffin_uk/auth-webauthn`

Passkey registration and authentication middleware with attestation, origin,
RP ID, challenge, signature, flag, and replay-counter validation.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-webauthn
```

```ts
import { webAuthn } from '@ngriffin_uk/auth-webauthn'

const auth = baseAuth.use(
  webAuthn({
    rpId: 'example.com',
    rpName: 'Example',
    origins: ['https://example.com'],
    store: credentialStore,
    requireUserVerification: true
  })
)
```

The service implements `WebAuthnStore`; `updateSignCount` must compare and
update atomically. Registration accepts none or packed self-attestation and
ES256 or RS256 credentials. Certificate attestation formats are rejected
rather than trusted without a certificate policy. Authenticator extension data
is validated as bounded CBOR, and backup eligibility cannot change after
registration.
