# `@ngriffin_uk/auth-provider-yahoo`

Yahoo OAuth/OIDC middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-yahoo
```

```ts
import { createYahooAuth } from "@ngriffin_uk/auth-provider-yahoo";

const auth = baseAuth.use(
  createYahooAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

Validate OIDC claims before using ID-token profile data.
