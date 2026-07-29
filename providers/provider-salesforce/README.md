# `@ngriffin_uk/auth-provider-salesforce`

Salesforce OAuth middleware for production, sandbox, or custom domains.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-salesforce
```

```ts
import { createSalesforceAuth } from "@ngriffin_uk/auth-provider-salesforce";

const auth = baseAuth.use(
  createSalesforceAuth("login.salesforce.com", {
    clientId,
    clientSecret,
    redirectUri,
    stateStore,
    resolveIdentity,
  })
);
```

Pass the Salesforce domain without a protocol or path.
