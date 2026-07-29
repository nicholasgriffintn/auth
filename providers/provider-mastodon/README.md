# `@ngriffin_uk/auth-provider-mastodon`

Mastodon OAuth middleware for a selected server.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-mastodon
```

```ts
import { createMastodonAuth } from "@ngriffin_uk/auth-provider-mastodon";

const auth = baseAuth.use(
  createMastodonAuth("https://mastodon.social", {
    clientId,
    clientSecret,
    redirectUri,
    stateStore,
    resolveIdentity,
  })
);
```

Validate or allowlist server URLs before passing user-selected instances.
