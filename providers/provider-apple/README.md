# `@ngriffin_uk/auth-provider-apple`

Sign in with Apple OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-apple
```

```ts
import {
  createAppleAuth,
  importApplePrivateKey,
} from "@ngriffin_uk/auth-provider-apple";

const privateKey = await importApplePrivateKey(pkcs8Key);
const auth = baseAuth.use(
  createAppleAuth({
    clientId,
    teamId,
    keyId,
    privateKey,
    redirectUri,
    stateStore,
    resolveIdentity,
  })
);
```

The middleware creates the short-lived ES256 client-secret JWT. Keep the Apple
private key outside application source and rotate it through your secret store.
