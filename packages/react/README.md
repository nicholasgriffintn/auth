# `@ngriffin_uk/auth-react`

Unstyled React components for complete authentication flows.

```sh
pnpm add react @ngriffin_uk/auth-react
```

```tsx
import { AuthFlow, AuthProvider } from '@ngriffin_uk/auth-react'

;<AuthProvider
  config={{
    capabilities: {
      magicLink: true,
      password: true,
      passkeys: true,
      signUp: true
    },
    providers: [{ id: 'github', label: 'Continue with GitHub' }]
  }}
>
  <AuthFlow />
</AuthProvider>
```

Your application must:

- expose a `POST /api/auth` endpoint that accepts `AuthRequest` and returns
  `AuthClientResult`;
- enable only the authentication methods and providers that its backend
  supports;
- style the supplied `auth-*` classes, or provide replacement class names.

Set `endpoint` only when the authentication API is hosted elsewhere. The
package provides the browser UI for OAuth, direct Apple sign-in, password and
magic-link flows, MFA, recovery codes, TOTP QR codes, and WebAuthn.
