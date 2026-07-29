# `@ngriffin_uk/auth-encoding`

Strict base16/hex, base32, base64, and base64url codecs.

```sh
pnpm add @ngriffin_uk/auth-encoding
```

```ts
import {
  decodeBase64Url,
  encodeBase32,
  encodeBase64Url,
} from "@ngriffin_uk/auth-encoding";

const token = encodeBase64Url(bytes);
const restored = decodeBase64Url(token);
const otpSecret = encodeBase32(bytes);
```

Malformed encodings throw `TypeError` rather than being decoded permissively.
