# `@ngriffin_uk/auth-provider-linkedin`

LinkedIn OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-linkedin
```

```ts
import { createLinkedInAuth } from "@ngriffin_uk/auth-provider-linkedin";

const auth = baseAuth.use(
  createLinkedInAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

The service owns profile retrieval and external-identity mapping.
