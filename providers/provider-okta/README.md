# `@ngriffin_uk/auth-provider-okta`

Okta OAuth/OIDC middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-okta
```

```ts
import { createOktaAuth } from "@ngriffin_uk/auth-provider-okta";

const auth = baseAuth.use(
  createOktaAuth("https://example.okta.com", {
    clientId,
    clientSecret,
    redirectUri,
    stateStore,
    resolveIdentity,
  })
);
```

Pass the HTTPS Okta organisation or custom authorisation-server base URL.
