# `@ngriffin_uk/auth-provider-atlassian`

Atlassian OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-atlassian
```

```ts
import { createAtlassianAuth } from "@ngriffin_uk/auth-provider-atlassian";

const auth = baseAuth.use(
  createAtlassianAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

The service owns OAuth state and maps the token response to an external
identity.
