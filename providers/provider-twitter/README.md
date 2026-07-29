# `@ngriffin_uk/auth-provider-twitter`

Twitter/X OAuth 2.0 middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-twitter
```

```ts
import { createTwitterAuth } from "@ngriffin_uk/auth-provider-twitter";

const auth = baseAuth.use(
  createTwitterAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

PKCE is enabled. Public clients can omit the client secret when permitted by
their application configuration.
