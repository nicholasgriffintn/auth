# `@ngriffin_uk/auth-provider-apple`

Sign in with Apple OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-apple
```

```ts
import { createAppleAuth, importApplePrivateKey } from '@ngriffin_uk/auth-provider-apple'

const privateKey = await importApplePrivateKey(pkcs8Key)
const auth = baseAuth.use(
  createAppleAuth({
    clientId,
    teamId,
    keyId,
    privateKey,
    redirectUri,
    stateStore,
    resolveIdentity
  })
)
```

The middleware creates the short-lived ES256 client-secret JWT. Keep the Apple
private key outside application source and rotate it through your secret store.

Native and popup clients that already receive an Apple identity token can use
the provider's direct implementation:

```ts
import { createAppleDirectAuth } from '@ngriffin_uk/auth-provider-apple'

const auth = baseAuth.use(
  createAppleDirectAuth({
    clientIds: [webClientId, iosClientId]
  })
)

const result = await auth.providers.apple.signIn({
  identityToken,
  nonce: originalNonce,
  name
})
```

Generate a fresh, unpredictable nonce for every sign-in attempt and pass its
SHA-256 digest to Apple. Keep the original nonce in the initiating client long
enough to submit it with the identity token. Configure every web or native
client ID that is allowed to sign in, and reject unverified email claims when
linking an identity to an existing account.
