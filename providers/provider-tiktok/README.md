# `@ngriffin_uk/auth-provider-tiktok`

TikTok OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-tiktok
```

```ts
import { createTikTokAuth } from "@ngriffin_uk/auth-provider-tiktok";

const auth = baseAuth.use(
  createTikTokAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

Use the TikTok client key as `clientId`.
