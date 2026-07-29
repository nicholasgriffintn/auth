# `@ngriffin_uk/auth-provider-vk`

VK OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-vk
```

```ts
import { createVKAuth } from "@ngriffin_uk/auth-provider-vk";

const auth = baseAuth.use(
  createVKAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

The service maps VK profile data to its external identity record.
