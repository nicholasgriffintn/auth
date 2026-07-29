# `@ngriffin_uk/auth-password`

Password sign-up, sign-in, verification, recovery, reset, and change-password
middleware for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-password @ngriffin_uk/auth-password-hash
```

```ts
import { passwordAuth } from "@ngriffin_uk/auth-password";
import { createArgon2idHasher } from "@ngriffin_uk/auth-password-hash/node";

const auth = baseAuth.use(
  passwordAuth({
    store: passwordStore,
    hasher: createArgon2idHasher(),
    emailVerification: { send: sendVerification },
    passwordReset: { send: sendPasswordReset },
  })
);
```

The service implements `PasswordStore` and delivery callbacks. Enforce email
uniqueness atomically and rate-limit every public operation. Unknown users and
incorrect passwords produce the same public credential error.
