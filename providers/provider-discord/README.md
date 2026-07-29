# `@ngriffin_uk/auth-provider-discord`

Discord OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-discord
```

```ts
import { createDiscordAuth } from "@ngriffin_uk/auth-provider-discord";

const auth = baseAuth.use(
  createDiscordAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

Configure the required Discord scopes in the provider options.
