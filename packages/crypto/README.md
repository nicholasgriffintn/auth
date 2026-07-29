# `@ngriffin_uk/auth-crypto`

Runtime-neutral Web Crypto helpers for secure randomness, SHA-2, HMAC,
constant-time comparison, RSA, and ECDSA.

```sh
pnpm add @ngriffin_uk/auth-crypto
```

```ts
import {
  constantTimeEqual,
  randomBytes,
  sha256,
} from "@ngriffin_uk/auth-crypto";

const token = randomBytes(32);
const digest = await sha256(token);
const matches = constantTimeEqual(digest, expectedDigest);
```

The package requires `globalThis.crypto` and fails closed when secure
cryptography is unavailable. Prefer the higher-level auth packages unless you
are implementing a protocol.
