# `@ngriffin_uk/auth-oauth2`

OAuth 2.0 and OpenID Connect middleware with state, PKCE, nonce, token refresh,
revocation, discovery, and verified ID-token support.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-oauth2
```

Most applications should install a package from `@ngriffin_uk/auth-provider-*`.
Use this package directly to define a provider that is not already included:

```ts
import {
  createOAuthProvider,
  defineOAuthProvider,
} from "@ngriffin_uk/auth-oauth2";

const definition = defineOAuthProvider({
  name: "example",
  authorizationEndpoint: "https://identity.example/authorize",
  tokenEndpoint: "https://identity.example/token",
  pkce: true,
});

const middleware = createOAuthProvider(definition, {
  clientId,
  redirectUri,
  stateStore,
  resolveIdentity,
});
```

The service supplies a single-use `OAuthStateStore`, maps external profile data
to `ExternalIdentity`, and persists refresh tokens itself when needed. OIDC ID
tokens must contain `sub`, `aud`, `exp`, and `iat`; multiple audiences also
require an `azp` value matching the client ID.
