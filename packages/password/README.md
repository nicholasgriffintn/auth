# `@ngriffin_uk/auth-password`

Password sign-up, sign-in, verification, recovery, reset, and change-password
middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-password @ngriffin_uk/auth-password-hash
```

```ts
import { passwordAuth } from '@ngriffin_uk/auth-password'
import { createArgon2idHasher } from '@ngriffin_uk/auth-password-hash/node'

const auth = baseAuth.use(
  passwordAuth({
    store: passwordStore,
    hasher: createArgon2idHasher(),
    emailVerification: { send: sendVerification },
    passwordReset: { send: sendPasswordReset }
  })
)
```

The service implements `PasswordStore` and delivery callbacks. Enforce email
uniqueness atomically and rate-limit every public operation. Unknown users and
incorrect passwords produce the same public credential error.

Use `verifyCredentials()` when another factor must complete before issuing a
session. Unlike `signIn()`, it validates the password and returns the user
without creating an authenticated session. The caller must enforce email
verification and other account-state policies before continuing.

When the configured hasher supports `verifyAndCheck`, successful sign-in
automatically replaces hashes that are marked for upgrade.
