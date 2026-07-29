# `@ngriffin_uk/auth-react`

Configurable, unstyled React components for password, OAuth, recovery, MFA,
custom, passkey, and challenge-selection flows.

```sh
pnpm add react @ngriffin_uk/auth-react
```

```tsx
import { AuthFlow, AuthProvider } from "@ngriffin_uk/auth-react";

<AuthProvider
  config={{
    transport,
    capabilities: { password: true, passkeys: true, signUp: true },
    providers: [{ id: "google", label: "Continue with Google" }],
    onRedirect: (url) => window.location.assign(url),
  }}
>
  <AuthFlow />
</AuthProvider>;
```

`transport.execute()` maps the serialisable UI request to service endpoints and
returns an `AuthClientResult`. Configure additional sign-up fields, copy,
classes, analytics, provider icons, TOTP QR rendering, and WebAuthn browser
handling through `AuthProviderConfig`. The package imports no router, server
framework, database, or provider SDK.
