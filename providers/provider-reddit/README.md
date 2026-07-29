# `@ngriffin_uk/auth-provider-reddit`

Reddit OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-reddit
```

```ts
import { createRedditAuth } from "@ngriffin_uk/auth-provider-reddit";

const auth = baseAuth.use(
  createRedditAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

Request only the Reddit scopes needed by the service.
