# `@ngriffin_uk/auth-provider-figma`

Figma OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-figma
```

```ts
import { createFigmaAuth } from "@ngriffin_uk/auth-provider-figma";

const auth = baseAuth.use(
  createFigmaAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

The service owns state persistence and profile-to-user mapping.
