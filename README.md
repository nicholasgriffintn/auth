# Auth

<p align="center">
  <img src="./assets/auth-logo.png" alt="Auth logo" width="220">
</p>

Reusable authentication packages for backend services and React applications.
The backend owns authentication flows; each consuming service owns its
database, cookies, HTTP routes, redirects, secrets, and domain user model.

## Packages

- `@ngriffin_uk/auth-core` provides sessions, opaque challenges, storage
  contracts, and typed middleware registration.
- `@ngriffin_uk/auth-password`, `auth-magic-link`, `auth-otp`, and
  `auth-webauthn` add local authentication capabilities.
- `@ngriffin_uk/auth-provider-*` packages add OAuth/OIDC providers. The Amazon
  Cognito provider also supports direct user-pool challenge flows.
- `@ngriffin_uk/auth-react` renders configurable, unstyled authentication
  screens through a service-supplied transport.
- The cookie, crypto, encoding, JWT, OAuth, password-hash, and request packages
  expose lower-level security primitives.

Install only what a service uses for example:

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-github
```

## Backend setup

Implement the storage ports with your service's database, then add provider
middleware:

```ts
import { createAuth } from '@ngriffin_uk/auth-core'
import { createGitHubAuth } from '@ngriffin_uk/auth-provider-github'

const auth = createAuth({
  users,
  sessions,
  challenges,
  identities
}).use(
  createGitHubAuth({
    clientId: env.GITHUB_CLIENT_ID,
    clientSecret: env.GITHUB_CLIENT_SECRET,
    redirectUri: 'https://app.example.com/auth/github/callback',
    stateStore: oauthStates,
    resolveIdentity: async (tokens) => loadGitHubIdentity(tokens.accessToken)
  })
)

const redirectUrl = await auth.providers.github.startAuthorization()
```

The service must:

- store only hashed session and continuation tokens;
- implement atomic uniqueness for users and external identities;
- encrypt upstream sessions, refresh tokens, and OTP secrets at rest;
- set its own `HttpOnly`, `Secure`, and appropriate `SameSite` cookies;
- rate-limit sign-in, sign-up, recovery, MFA, and callback endpoints;
- translate safe `AuthError` codes into its HTTP response format.

## React setup

The UI calls one transport owned by the application. This keeps routing,
cookies, server functions, and provider SDKs outside the component package.

```tsx
import { AuthFlow, AuthProvider } from '@ngriffin_uk/auth-react'

;<AuthProvider
  config={{
    transport: {
      execute: (request) =>
        fetch('/api/auth', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(request)
        }).then((response) => response.json())
    },
    capabilities: {
      password: true,
      passkeys: true,
      signUp: true,
      recovery: true
    },
    providers: [{ id: 'github', label: 'Continue with GitHub' }],
    onRedirect: (url) => window.location.assign(url)
  }}
>
  <AuthFlow />
</AuthProvider>
```

Components ship without CSS. Use the `auth-*` classes, `data-auth-view`,
`data-auth-screen`, and `data-auth-challenge` attributes, or provide class
names through `AuthProviderConfig`.

## Development and publishing

```sh
pnpm check
pnpm changeset
pnpm changeset version
pnpm run publish
```

`pnpm run publish` builds every package before publishing it. Do not run
`pnpm publish -r` directly because that bypasses the workspace build.

See each package README for its public entry points and required service
contracts. See [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) for acknowledgements.
