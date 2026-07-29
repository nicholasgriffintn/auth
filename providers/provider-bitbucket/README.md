# `@ngriffin_uk/auth-provider-bitbucket`

Bitbucket OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-bitbucket
```

```ts
import { createBitbucketAuth } from "@ngriffin_uk/auth-provider-bitbucket";

const auth = baseAuth.use(
  createBitbucketAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

The service owns callback routes, state persistence, and identity mapping.
