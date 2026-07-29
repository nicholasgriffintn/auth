# `@ngriffin_uk/auth-provider-facebook`

Facebook OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-facebook
```

```ts
import { createFacebookAuth } from "@ngriffin_uk/auth-provider-facebook";

const auth = baseAuth.use(
  createFacebookAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

The service fetches the required profile fields in `resolveIdentity`.
