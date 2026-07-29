# `@ngriffin_uk/auth-provider-linear`

Linear OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-linear
```

```ts
import { createLinearAuth } from "@ngriffin_uk/auth-provider-linear";

const auth = baseAuth.use(
  createLinearAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

Configure only the scopes required by the consuming service.
