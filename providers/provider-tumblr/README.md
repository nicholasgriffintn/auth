# `@ngriffin_uk/auth-provider-tumblr`

Tumblr OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-tumblr
```

```ts
import { createTumblrAuth } from "@ngriffin_uk/auth-provider-tumblr";

const auth = baseAuth.use(
  createTumblrAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

The service owns state persistence, token storage, and identity mapping.
