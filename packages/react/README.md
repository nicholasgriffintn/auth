# `@ngriffin_uk/auth-react`

Configurable, unstyled React components for password, magic-link, OAuth,
recovery, MFA, custom, passkey, and challenge-selection flows.

```sh
pnpm add react @ngriffin_uk/auth-react
```

```tsx
import { AuthFlow, AuthProvider, AuthSecuritySetup } from '@ngriffin_uk/auth-react'

;<AuthProvider
  config={{
    transport,
    capabilities: {
      magicLink: true,
      password: true,
      passkeys: true,
      signUp: true
    },
    providers: [{ id: 'google', label: 'Continue with Google' }],
    onRedirect: (url) => window.location.assign(url)
  }}
>
  <AuthFlow />
  {user ? <AuthSecuritySetup status={{ totpConfigured: true, passkeyCount: 1 }} /> : null}
</AuthProvider>
```

`transport.execute()` maps the serialisable UI request to service endpoints and
returns an `AuthClientResult`. Configure additional sign-up fields, copy,
classes, analytics, provider icons, TOTP QR rendering, and WebAuthn browser
handling through `AuthProviderConfig`. `AuthSecuritySetup` starts TOTP and
WebAuthn registration through the same transport and renders their package
challenge screens. The package imports no router, server framework, database,
or provider SDK.

Sign-in transports can return a WebAuthn assertion challenge with a
`software_token_mfa` alternative. The UI presents the passkey first, then lets
the user switch to an authenticator or one-use recovery code.

When `magicLink` is enabled, handle `request_magic_link` in the transport.
Return `completed` with a safe status message for clickable links, or return an
`email_otp` challenge when the user must enter an emailed code.
