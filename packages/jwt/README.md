# `@ngriffin_uk/auth-jwt`

JWT/JWS parsing, signing, signature verification, claim validation, and local
or remote JWKS key resolution.

```sh
pnpm add @ngriffin_uk/auth-jwt
```

```ts
import { createRemoteJwksResolver, verifyJwt } from '@ngriffin_uk/auth-jwt'

const key = createRemoteJwksResolver({
  url: 'https://issuer.example/.well-known/jwks.json'
})

const claims = await verifyJwt(token, {
  algorithms: ['RS256'],
  key,
  issuer: 'https://issuer.example',
  audience: 'my-client'
})
```

For application-owned HMAC tokens, import a text secret once and reuse the
resulting key:

```ts
const key = await importHmacSecret(process.env.JWT_SECRET, 'HS256')
const token = await signJwt(claims, { algorithm: 'HS256', key })
```

Use a randomly generated secret of at least 32 bytes and rotate it through your
secret store.

Always provide an explicit algorithm allowlist and validate issuer, audience,
time claims, and subject where the protocol requires them. `parseJwt()` does
not verify a token.
