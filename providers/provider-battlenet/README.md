# `@ngriffin_uk/auth-provider-battlenet`

Battle.net OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-battlenet
```

```ts
import { createBattleNetAuth } from "@ngriffin_uk/auth-provider-battlenet";

const auth = baseAuth.use(
  createBattleNetAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

Provide scopes and map the returned access token in `resolveIdentity`.
