import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { DEFAULT_COPY } from "../config.js";
import type { AuthClientChallenge } from "../types.js";
import { challengeFields, challengeTitle } from "./challenge-fields.js";

describe("authentication challenge presentation", () => {
  it("builds password-reset fields from the shared copy", () => {
    const fields = challengeFields(challenge("password_reset"), DEFAULT_COPY);

    assert.deepEqual(
      fields.map((field) => field.name),
      ["code", "newPassword", "confirmPassword"]
    );
    assert.equal(fields[1]?.label, DEFAULT_COPY.newPasswordLabel);
    assert.equal(fields[2]?.label, DEFAULT_COPY.confirmPasswordLabel);
  });

  it("builds a recovery-code-compatible MFA field", () => {
    const fields = challengeFields(
      challenge("software_token_mfa", { method: "totp_or_recovery" }),
      DEFAULT_COPY
    );

    assert.equal(fields[0]?.inputMode, "text");
    assert.equal(fields[0]?.label, DEFAULT_COPY.totpOrRecoveryCodeLabel);
    assert.equal(fields[0]?.description, DEFAULT_COPY.totpOrRecoveryDescription);
  });

  it("uses the WebAuthn ceremony to choose the challenge title", () => {
    assert.equal(
      challengeTitle(
        challenge("webauthn", { ceremony: "registration" }),
        DEFAULT_COPY
      ),
      DEFAULT_COPY.passkeySetupLabel
    );
    assert.equal(
      challengeTitle(
        challenge("webauthn", { ceremony: "authentication" }),
        DEFAULT_COPY
      ),
      DEFAULT_COPY.passkeyChallengeTitle
    );
  });
});

function challenge(
  kind: AuthClientChallenge["kind"],
  parameters?: Readonly<Record<string, string>>
): AuthClientChallenge {
  return {
    kind,
    continuationToken: "challenge-token",
    expiresAt: "2026-07-30T12:00:00.000Z",
    ...(parameters ? { parameters } : {}),
  };
}
