# `@ngriffin_uk/auth-provider-twitch`

Twitch OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-twitch
```

```ts
import { createTwitchAuth } from "@ngriffin_uk/auth-provider-twitch";

const auth = baseAuth.use(
  createTwitchAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

Configure Twitch scopes explicitly for the service's required capabilities.
