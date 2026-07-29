# `@ngriffin_uk/auth-provider-notion`

Notion OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-notion
```

```ts
import { createNotionAuth } from "@ngriffin_uk/auth-provider-notion";

const auth = baseAuth.use(
  createNotionAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

The provider includes Notion's required owner/user authorisation parameters.
