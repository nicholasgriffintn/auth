# `@ngriffin_uk/auth-provider-gitea`

Gitea OAuth middleware for hosted or self-hosted instances.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-gitea
```

```ts
import { createGiteaAuth } from "@ngriffin_uk/auth-provider-gitea";

const auth = baseAuth.use(
  createGiteaAuth("https://git.example.com", {
    clientId,
    clientSecret,
    redirectUri,
    stateStore,
    resolveIdentity,
  })
);
```

Pass the HTTPS instance base URL without OAuth endpoint paths.
