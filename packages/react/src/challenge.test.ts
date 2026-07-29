import assert from "node:assert/strict";
import { test } from "node:test";

import { alternativeAuthChallenge } from "./challenge.js";

test("resolves a server-issued fallback authentication challenge", () => {
  assert.deepEqual(
    alternativeAuthChallenge({
      kind: "webauthn",
      continuationToken: "passkey-token",
      expiresAt: "2026-01-01T00:10:00.000Z",
      parameters: {
        alternativeChallengeKind: "software_token_mfa",
        alternativeContinuationToken: "otp-token",
        alternativeExpiresAt: "2026-01-01T00:10:00.000Z",
        alternativeMethod: "totp_or_recovery",
      },
    }),
    {
      kind: "software_token_mfa",
      continuationToken: "otp-token",
      expiresAt: "2026-01-01T00:10:00.000Z",
      parameters: { method: "totp_or_recovery" },
    }
  );
});
