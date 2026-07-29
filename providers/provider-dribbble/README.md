# `@ngriffin_uk/auth-provider-dribbble`

Dribbble OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-dribbble
```

```ts
import { createDribbbleAuth } from "@ngriffin_uk/auth-provider-dribbble";

const auth = baseAuth.use(
  createDribbbleAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

The service supplies OAuth state storage and external-identity resolution.
