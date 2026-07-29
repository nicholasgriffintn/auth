# `@ngriffin_uk/auth-otp`

HOTP/TOTP generation and verification, key URIs, recovery codes, replay
protection, and `auth-core` MFA middleware.

```sh
pnpm add @ngriffin_uk/auth-core @ngriffin_uk/auth-otp
```

```ts
import { otpAuth } from "@ngriffin_uk/auth-otp";

const auth = baseAuth.use(
  otpAuth({
    issuer: "Example",
    store: otpStore,
  })
);
```

Implement `OtpStore` with atomic `advanceStep` and recovery-code consumption.
Persist `lastAcceptedStep` from `saveCredential` in the same write as the
encrypted OTP secret. The setup result exposes the secret and URI once so the
service can render a QR code.
