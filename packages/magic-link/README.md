# `@ngriffin_uk/auth-magic-link`

Single-use email link and verification-code authentication for `auth-core`.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-magic-link
```

```ts
import { magicLinkAuth } from '@ngriffin_uk/auth-magic-link'

const auth = baseAuth.use(
  magicLinkAuth({
    mode: 'link',
    resolveUser: (email) => users.findOrCreateByVerifiedEmail(email),
    send: ({ email, token }) => emailService.sendSignInLink(email, `${appUrl}/auth/verify?token=${token}`)
  })
)
```

Use `mode: "code"` to email a short code. Return the request result to
`@ngriffin_uk/auth-react`, then pass its continuation token and the submitted
code to `verify()` or `authenticate()`.

The service must encrypt challenge payloads, consume successful challenges
atomically, rate-limit requests and verification attempts, and return the same
public response whether or not an account exists. Re-check account eligibility
inside `resolveUser`; an email address becomes trusted only after successful
challenge verification.
