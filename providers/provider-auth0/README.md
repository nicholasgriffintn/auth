# `@ngriffin_uk/auth-provider-auth0`

Auth0 OAuth/OIDC middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-auth0
```

```ts
import { createAuth0Auth } from "@ngriffin_uk/auth-provider-auth0";

const auth = baseAuth.use(
  createAuth0Auth("tenant.eu.auth0.com", {
    clientId,
    clientSecret,
    redirectUri,
    stateStore,
    resolveIdentity,
  })
);
```

Pass the tenant domain without a protocol or path.
