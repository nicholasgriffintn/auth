import type {
  AuthChallengeKind,
  AuthSession,
  AuthUser,
} from "./types.js";

export interface PublicChallenge<
  Kind extends AuthChallengeKind = AuthChallengeKind,
> {
  readonly kind: Kind;
  readonly continuationToken: string;
  readonly expiresAt: Date;
  readonly parameters?: Readonly<Record<string, string | readonly string[]>>;
}

interface ChallengeFlowResult<
  Status extends string,
  Kind extends AuthChallengeKind,
> {
  readonly status: Status;
  readonly challenge: PublicChallenge<Kind>;
}

export type AuthFlowResult<User extends AuthUser> =
  | {
      readonly status: "authenticated";
      readonly session: AuthSession<User>;
    }
  | ChallengeFlowResult<
      "email_verification_required",
      "email_verification"
    >
  | ChallengeFlowResult<"password_reset_required", "password_reset">
  | ChallengeFlowResult<"new_password_required", "new_password">
  | ChallengeFlowResult<"mfa_setup_required", "mfa_setup">
  | ChallengeFlowResult<
      "mfa_challenge_required",
      "email_otp" | "sms_mfa" | "sms_otp" | "software_token_mfa"
    >
  | ChallengeFlowResult<"challenge_selection_required", "mfa_selection">
  | ChallengeFlowResult<"custom_challenge_required", "custom" | "password">
  | ChallengeFlowResult<"webauthn_challenge_required", "webauthn">
  | ChallengeFlowResult<"unsupported_challenge", "unsupported">
  | {
      readonly status: "redirect_required";
      readonly provider: string;
      readonly url: URL;
    };
