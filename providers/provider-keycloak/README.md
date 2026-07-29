# `@ngriffin_uk/auth-provider-keycloak`

Keycloak OAuth/OIDC middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-keycloak
```

```ts
import { createKeyCloakAuth } from "@ngriffin_uk/auth-provider-keycloak";

const auth = baseAuth.use(
  createKeyCloakAuth("https://identity.example.com/realms/example", {
    clientId,
    clientSecret,
    redirectUri,
    stateStore,
    resolveIdentity,
  })
);
```

Pass the complete HTTPS realm URL.
