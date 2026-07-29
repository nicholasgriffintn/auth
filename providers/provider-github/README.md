# `@ngriffin_uk/auth-provider-github`

GitHub OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-github
```

```ts
import { createGitHubAuth } from "@ngriffin_uk/auth-provider-github";

const auth = baseAuth.use(
  createGitHubAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

GitHub does not support PKCE for this endpoint, so state must be stored and
consumed atomically.
