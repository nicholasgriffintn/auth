# `@ngriffin_uk/auth-provider-spotify`

Spotify OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-spotify
```

```ts
import { createSpotifyAuth } from "@ngriffin_uk/auth-provider-spotify";

const auth = baseAuth.use(
  createSpotifyAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

Persist refresh tokens in the consuming service when long-lived Spotify access
is required.
