# `@ngriffin_uk/auth-provider-slack`

Slack OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-slack
```

```ts
import { createSlackAuth } from "@ngriffin_uk/auth-provider-slack";

const auth = baseAuth.use(
  createSlackAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

Map the Slack user or workspace identity explicitly in `resolveIdentity`.
