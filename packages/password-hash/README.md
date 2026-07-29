# `@ngriffin_uk/auth-password-hash`

Password-hasher contracts plus dependency-free Argon2id, scrypt, and PBKDF2
implementations.

```sh
pnpm add @ngriffin_uk/auth-password-hash
```

```ts
import { createArgon2idHasher } from "@ngriffin_uk/auth-password-hash/node";

const hasher = createArgon2idHasher();
const hash = await hasher.hash(password);
const result = await hasher.verifyAndCheck(password, hash);
```

Node's built-in Argon2id requires Node 24.7 or newer. The Node entry point also
exports scrypt; the `pbkdf2` entry point uses Web Crypto. Legacy formats such as
bcrypt are intentionally not implemented by an unaudited dependency—supply a
`PasswordHasher` adapter in the consuming service if migration compatibility is
required.
