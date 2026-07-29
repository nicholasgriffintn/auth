# `@ngriffin_uk/auth-provider-microsoft-entra-id`

Microsoft Entra ID OAuth/OIDC middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-microsoft-entra-id
```

```ts
import { createMicrosoftEntraIdAuth } from "@ngriffin_uk/auth-provider-microsoft-entra-id";

const auth = baseAuth.use(
  createMicrosoftEntraIdAuth("common", {
    clientId,
    clientSecret,
    redirectUri,
    stateStore,
    resolveIdentity,
  })
);
```

Use a tenant ID for single-tenant applications, or an explicitly chosen
Microsoft tenant selector.
