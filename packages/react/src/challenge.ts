import type {
  AuthChallengeKind,
  AuthClientChallenge,
} from "./types.js";

export function alternativeAuthChallenge(
  challenge: AuthClientChallenge
): AuthClientChallenge | null {
  const parameters = challenge.parameters;
  const kind = parameters?.["alternativeChallengeKind"];
  const continuationToken = parameters?.["alternativeContinuationToken"];
  const expiresAt = parameters?.["alternativeExpiresAt"];
  const method = parameters?.["alternativeMethod"];
  if (
    typeof kind !== "string" ||
    !isAuthChallengeKind(kind) ||
    typeof continuationToken !== "string" ||
    continuationToken.length === 0 ||
    typeof expiresAt !== "string" ||
    !Number.isFinite(Date.parse(expiresAt))
  ) {
    return null;
  }
  return {
    kind,
    continuationToken,
    expiresAt,
    ...(typeof method === "string" ? { parameters: { method } } : {}),
  };
}

function isAuthChallengeKind(value: string): value is AuthChallengeKind {
  return [
    "custom",
    "email_otp",
    "email_verification",
    "mfa_selection",
    "mfa_setup",
    "new_password",
    "password",
    "password_reset",
    "sms_mfa",
    "sms_otp",
    "software_token_mfa",
    "unsupported",
    "webauthn",
  ].includes(value);
}
