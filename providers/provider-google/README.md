# `@ngriffin_uk/auth-provider-google`

Google OAuth/OIDC middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-google
```

```ts
import { createGoogleAuth } from "@ngriffin_uk/auth-provider-google";

const auth = baseAuth.use(
  createGoogleAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

Configure OIDC verification when using ID-token claims; never trust a decoded
token without signature and issuer validation.
