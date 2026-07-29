import {
  AuthError,
  type AuthFlowResult,
  type AuthPlugin,
  type AuthPluginContext,
  type AuthUser,
} from "@ngriffin_uk/auth-core";
import { randomBytes } from "@ngriffin_uk/auth-crypto";
import {
  decodeBase64Url,
  encodeBase32,
  encodeBase64Url,
} from "@ngriffin_uk/auth-encoding";

import {
  createRecoveryCodes,
  hashRecoveryCode,
  validateRecoveryCodeCount,
} from "./recovery-code.js";
import { verifyTotp } from "./totp.js";
import type {
  OtpOperations,
  OtpPluginConfig,
} from "./types.js";
import { createTotpUri } from "./uri.js";
import { validateOtpParameters } from "./validation.js";

export function otpAuth<User extends AuthUser>(
  config: OtpPluginConfig
): AuthPlugin<"otp", OtpOperations<User>, User> {
  validateConfig(config);
  return {
    name: "otp",
    install(context) {
      return {
        startSetup: (input) => startSetup(context, config, input),
        verifySetup: (input) => verifySetup(context, config, input),
        createChallenge: (userId) =>
          createChallenge(context, config, userId),
        verifyChallenge: (input) =>
          verifyChallenge(context, config, input),
        useRecoveryCode: (input) =>
          useRecoveryCode(context, config, input),
      };
    },
  };
}

async function startSetup<User extends AuthUser>(
  context: AuthPluginContext<User>,
  config: OtpPluginConfig,
  input: { readonly userId: string; readonly accountName: string }
): Promise<AuthFlowResult<User>> {
  if (
    typeof input.accountName !== "string" ||
    !input.accountName.trim() ||
    input.accountName.length > 320
  ) {
    throw new AuthError("invalid_input", "OTP account name is invalid.");
  }
  const user = await context.users.findById(input.userId);
  if (!user) throw new AuthError("invalid_input");
  const secret = randomBytes(20);
  const recoveryCodes = createRecoveryCodes(config.recoveryCodeCount ?? 10);
  const recoveryCodeHashes = await Promise.all(
    recoveryCodes.map(hashRecoveryCode)
  );
  const issued = await context.issueChallenge("otp", "mfa_setup", {
    userId: user.id,
    secret: encodeBase64Url(secret),
    recoveryCodeHashes,
  });
  const uri = createTotpUri({
    issuer: config.issuer,
    accountName: input.accountName,
    secret,
    ...config.options,
  });
  return {
    status: "mfa_setup_required",
    challenge: {
      kind: "mfa_setup",
      continuationToken: issued.token,
      expiresAt: issued.expiresAt,
      parameters: {
        secret: encodeBase32(secret),
        uri: uri.href,
        recoveryCodes,
      },
    },
  };
}

async function verifySetup<User extends AuthUser>(
  context: AuthPluginContext<User>,
  config: OtpPluginConfig,
  input: {
    readonly token: string;
    readonly code: string;
    readonly expectedUserId?: string;
  }
): Promise<AuthFlowResult<User>> {
  const challenge = await context.consumeChallenge(input.token, "otp", [
    "mfa_setup",
  ]);
  const userId = payloadString(challenge.payload, "userId");
  if (input.expectedUserId && input.expectedUserId !== userId) {
    throw new AuthError("challenge_mismatch");
  }
  const secret = decodeSecret(challenge.payload);
  const verification = await verifyTotp(
    input.code,
    secret,
    context.now(),
    config.options
  );
  if (!verification.valid || verification.step === undefined) {
    throw new AuthError("invalid_credentials", "The verification code is invalid.");
  }
  await config.store.saveCredential({
    userId,
    secret,
    lastAcceptedStep: verification.step,
    recoveryCodeHashes: payloadStrings(
      challenge.payload,
      "recoveryCodeHashes"
    ),
  });
  return authenticated(context, userId);
}

async function createChallenge<User extends AuthUser>(
  context: AuthPluginContext<User>,
  config: OtpPluginConfig,
  userId: string
): Promise<AuthFlowResult<User>> {
  const [user, credential] = await Promise.all([
    context.users.findById(userId),
    config.store.findCredential(userId),
  ]);
  if (!user || !credential) throw new AuthError("invalid_input");
  const issued = await context.issueChallenge(
    "otp",
    "software_token_mfa",
    { userId }
  );
  return {
    status: "mfa_challenge_required",
    challenge: {
      kind: "software_token_mfa",
      continuationToken: issued.token,
      expiresAt: issued.expiresAt,
    },
  };
}

async function verifyChallenge<User extends AuthUser>(
  context: AuthPluginContext<User>,
  config: OtpPluginConfig,
  input: { readonly token: string; readonly code: string }
): Promise<AuthFlowResult<User>> {
  const userId = await consumeUserChallenge(context, input.token);
  const credential = await config.store.findCredential(userId);
  if (!credential) throw new AuthError("invalid_credentials");
  const verification = await verifyTotp(
    input.code,
    credential.secret,
    context.now(),
    {
      ...config.options,
      ...(credential.lastAcceptedStep === undefined
        ? {}
        : { afterStep: credential.lastAcceptedStep }),
    }
  );
  if (
    !verification.valid ||
    verification.step === undefined ||
    !(await config.store.advanceStep(userId, verification.step))
  ) {
    throw new AuthError("invalid_credentials", "The verification code is invalid.");
  }
  return authenticated(context, userId);
}

async function useRecoveryCode<User extends AuthUser>(
  context: AuthPluginContext<User>,
  config: OtpPluginConfig,
  input: { readonly token: string; readonly code: string }
): Promise<AuthFlowResult<User>> {
  const userId = await consumeUserChallenge(context, input.token);
  const codeHash = await hashRecoveryCode(input.code);
  if (
    !codeHash ||
    !(await config.store.consumeRecoveryCode(
      userId,
      codeHash
    ))
  ) {
    throw new AuthError("invalid_credentials", "The recovery code is invalid.");
  }
  return authenticated(context, userId);
}

async function consumeUserChallenge<User extends AuthUser>(
  context: AuthPluginContext<User>,
  token: string
): Promise<string> {
  const challenge = await context.consumeChallenge(token, "otp", [
    "software_token_mfa",
  ]);
  return payloadString(challenge.payload, "userId");
}

async function authenticated<User extends AuthUser>(
  context: AuthPluginContext<User>,
  userId: string
): Promise<AuthFlowResult<User>> {
  const user = await context.users.findById(userId);
  if (!user) throw new AuthError("challenge_expired");
  const session = await context.issueSession(userId);
  return {
    status: "authenticated",
    session: { user, token: session.token, expiresAt: session.expiresAt },
  };
}

function decodeSecret(payload: Readonly<Record<string, unknown>>): Uint8Array {
  return decodeBase64Url(payloadString(payload, "secret"));
}

function payloadString(
  payload: Readonly<Record<string, unknown>>,
  field: string
): string {
  const value = payload[field];
  if (typeof value !== "string") throw new AuthError("challenge_mismatch");
  return value;
}

function validateConfig(config: OtpPluginConfig): void {
  if (
    typeof config.issuer !== "string" ||
    !config.issuer.trim() ||
    config.issuer.length > 128
  ) {
    throw new TypeError("OTP issuer is invalid.");
  }
  validateRecoveryCodeCount(config.recoveryCodeCount ?? 10);
  const options = config.options ?? {};
  validateOtpParameters(
    new Uint8Array(16),
    options.digits ?? 6,
    options.algorithm ?? "SHA-1"
  );
  if (
    options.periodSeconds !== undefined &&
    (!Number.isSafeInteger(options.periodSeconds) ||
      options.periodSeconds < 1)
  ) {
    throw new TypeError("TOTP period must be a positive integer.");
  }
}

function payloadStrings(
  payload: Readonly<Record<string, unknown>>,
  field: string
): readonly string[] {
  const value = payload[field];
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string")
  ) {
    throw new AuthError("challenge_mismatch");
  }
  return value;
}
