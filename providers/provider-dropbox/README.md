# `@ngriffin_uk/auth-provider-dropbox`

Dropbox OAuth middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-dropbox
```

```ts
import { createDropboxAuth } from "@ngriffin_uk/auth-provider-dropbox";

const auth = baseAuth.use(
  createDropboxAuth({ clientId, clientSecret, redirectUri, stateStore, resolveIdentity })
);
```

Persist refresh tokens in the consuming service when requesting offline access.
