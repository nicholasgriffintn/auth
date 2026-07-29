# `@ngriffin_uk/auth-provider-gitlab`

GitLab OAuth middleware for GitLab.com or self-hosted instances.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-gitlab
```

```ts
import { createGitLabAuth } from "@ngriffin_uk/auth-provider-gitlab";

const auth = baseAuth.use(
  createGitLabAuth("https://gitlab.com", {
    clientId,
    clientSecret,
    redirectUri,
    stateStore,
    resolveIdentity,
  })
);
```

Pass the HTTPS instance base URL.
