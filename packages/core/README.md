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

This is for the basic implementation only, see the below section for more information on how to implement the stores and middleware.

## Implement the stores

`auth-core` owns the authentication flow, but not persistence. Adapt your
database repositories to its store interfaces:

```ts
import {
  createAuth,
  type AuthChallengeRecord,
  type AuthUser,
  type ChallengeStore,
  type IdentityStore,
  type SessionStore,
  type UserStore,
} from "@ngriffin_uk/auth-core";

interface AppUser extends AuthUser {
  readonly displayName: string;
}

const users: UserStore<AppUser> = {
  findById: (userId) => userRepository.findById(userId),
};

const sessions: SessionStore = {
  create: (record) => sessionRepository.insert(record),
  findByTokenHash: (tokenHash) =>
    sessionRepository.findByTokenHash(tokenHash),
  deleteByTokenHash: (tokenHash) =>
    sessionRepository.deleteByTokenHash(tokenHash),
};

const challenges: ChallengeStore = {
  async create(record) {
    await challengeRepository.insert({
      ...record,
      payload: await encryption.encryptJson(record.payload),
    });
  },
  async consumeByTokenHash(tokenHash) {
    // This must atomically delete and return the row so a token cannot be reused.
    const row = await challengeRepository.takeByTokenHash(tokenHash);
    if (!row) return null;

    return {
      ...row,
      payload: await encryption.decryptJson(row.payload),
    } satisfies AuthChallengeRecord;
  },
};

const identities: IdentityStore<AppUser> = {
  findUser: (provider, providerSubject) =>
    identityRepository.findUser(provider, providerSubject),
  resolve: (identity) =>
    database.transaction(async (transaction) => {
      const existing = await transaction.identities.findUser(
        identity.provider,
        identity.providerSubject,
      );
      if (existing) return existing;

      const user = await transaction.users.createFromIdentity(identity);
      await transaction.identities.insert({
        provider: identity.provider,
        providerSubject: identity.providerSubject,
        userId: user.id,
        email: identity.email,
        emailVerified: identity.emailVerified,
        claims: identity.claims,
      });
      return user;
    }),
};

const auth = createAuth({
  users,
  sessions,
  challenges,
  identities,
});
```

The repository names above are placeholders for your ORM or database layer.
Preserve these storage rules:

- Store `AuthSessionRecord.tokenHash` as the session lookup key. The raw token
  is returned only by `createSession`; send it in a secure cookie and never log
  or persist it.
- Store `AuthChallengeRecord.tokenHash` as the continuation lookup key.
  `consumeByTokenHash` must atomically delete and return the record.
- Encrypt and authenticate the complete challenge `payload` before writing it.
  Use a service-managed key and authenticated encryption such as AES-GCM.
- Index session and challenge hashes uniquely, index their expiry timestamps,
  and delete expired records periodically.
- Make `(provider, providerSubject)` unique. Do not link accounts by an
  unverified email address in `IdentityStore.resolve`.

`auth-core` hashes raw session and continuation tokens with SHA-256 before it
calls a store. Store adapters must not hash them again.
