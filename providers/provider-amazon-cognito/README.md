# `@ngriffin_uk/auth-provider-amazon-cognito`

Amazon Cognito middleware for hosted OAuth/OIDC and direct user-pool
authentication.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-provider-amazon-cognito
```

Use hosted OAuth with a Cognito domain:

```ts
import { createAmazonCognitoAuth } from '@ngriffin_uk/auth-provider-amazon-cognito'

const auth = baseAuth.use(
  createAmazonCognitoAuth('example.auth.eu-west-2.amazoncognito.com', {
    clientId,
    clientSecret,
    redirectUri,
    stateStore,
    resolveIdentity
  })
)
```

Use the same provider package for direct challenges:

```ts
import { createAmazonCognitoDirectAuth } from '@ngriffin_uk/auth-provider-amazon-cognito'

const auth = baseAuth.use(
  createAmazonCognitoDirectAuth({
    region: 'eu-west-2',
    userPoolId: 'eu-west-2_example',
    clientId,
    clientSecret,
    onTokens: persistEncryptedTokens
  })
)
```

Direct mode covers sign-up/confirmation, password authentication and recovery,
refresh/revocation, sign-out, SMS/email/TOTP MFA, MFA setup, new-password,
challenge selection, custom challenges, and WebAuthn. Cognito sessions remain
inside the service-owned `ChallengeStore`; JWTs are verified against the user
pool JWKS before identity resolution.

Configure a durable challenge store that supports challenge lookup as well as
single-use consumption. This keeps confirmation, recovery, and MFA challenges
retryable after Cognito rejects an incorrect code. Direct mode uses Cognito's
public client APIs and does not require AWS access keys.
