# `@ngriffin_uk/auth-provider-polar`

Polar OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-polar
```

```ts
import { createPolarAuth } from "@ngriffin_uk/auth-provider-polar";

const auth = baseAuth.use(
  createPolarAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

The middleware selects the appropriate client authentication mode from the
provided credentials.
