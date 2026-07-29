# `@ngriffin_uk/auth-core`

Backend configuration, sessions, opaque challenges, and typed authentication
middleware. The package has no database, cookie, or framework dependency.

```sh
pnpm add @ngriffin_uk/auth-core
```

```ts
import { createAuth } from "@ngriffin_uk/auth-core";

const auth = createAuth({
  users,
  sessions,
  challenges,
  identities,
  sessionTtlMs: 30 * 24 * 60 * 60 * 1000,
});

const configured = auth.use(providerMiddleware);
```

Implement `UserStore`, `SessionStore`, `ChallengeStore`, and, for federated
identity, `IdentityStore` in the consuming service. Session and continuation
tokens are returned raw once; stores receive only their SHA-256 hashes.
Challenge payloads can contain upstream sessions or secrets, so encrypt them at
the storage boundary.
