import {
  AuthError,
  type AuthFlowResult,
  type AuthPluginContext,
  type AuthUser,
} from "@ngriffin_uk/auth-core";

import type {
  PasswordInput,
  PasswordPluginConfig,
  PasswordPolicy,
} from "./types.js";
import {
  validateCredentialInput,
  validatePasswordInput,
  normaliseEmailInput,
} from "./validation.js";

export interface PasswordRuntime<User extends AuthUser> {
  readonly context: AuthPluginContext<User>;
  readonly config: PasswordPluginConfig<User>;
  readonly normaliseEmail: (email: string) => string;
  readonly policy: PasswordPolicy;
}

export async function signUp<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  input: PasswordInput
): Promise<AuthFlowResult<User>> {
  const startedAt = performance.now();
  const email = normaliseEmailInput(input.email, runtime.normaliseEmail);
  validatePasswordInput({ ...input, email }, runtime.policy);

  try {
    const existing = await runtime.config.store.findByEmail(email);
    if (existing) throw new AuthError("email_in_use");
    const passwordHash = await runtime.config.hasher.hash(input.password);
    const user = await runtime.config.store.create({
      email,
      passwordHash,
      emailVerified: !runtime.config.emailVerification,
    });
    const result = runtime.config.emailVerification
      ? await issueEmailVerification(runtime, user)
      : await authenticated(runtime, user);
    report(runtime, "password.sign_up", "success", startedAt);
    return result;
  } catch (cause) {
    report(
      runtime,
      "password.sign_up",
      cause instanceof AuthError ? "rejected" : "error",
      startedAt,
      cause instanceof AuthError ? cause.code : "storage_error"
    );
    throw safeFailure(cause);
  }
}

export async function signIn<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  input: PasswordInput
): Promise<AuthFlowResult<User>> {
  const startedAt = performance.now();
  const email = normaliseEmailInput(input.email, runtime.normaliseEmail);
  validateCredentialInput({ ...input, email });
  try {
    const account = await verifiedPasswordAccount(runtime, email, input.password);
    const result =
      !account.emailVerified && runtime.config.emailVerification
        ? await issueEmailVerification(runtime, account.user)
        : await authenticated(runtime, account.user);
    report(runtime, "password.sign_in", "success", startedAt);
    return result;
  } catch (cause) {
    reportFailure(runtime, "password.sign_in", startedAt, cause);
    throw safeFailure(cause);
  }
}

export async function verifyCredentials<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  input: PasswordInput
): Promise<User> {
  const startedAt = performance.now();
  const email = normaliseEmailInput(input.email, runtime.normaliseEmail);
  validateCredentialInput({ ...input, email });
  try {
    const account = await verifiedPasswordAccount(runtime, email, input.password);
    report(runtime, "password.verify_credentials", "success", startedAt);
    return account.user;
  } catch (cause) {
    reportFailure(runtime, "password.verify_credentials", startedAt, cause);
    throw safeFailure(cause);
  }
}

export async function verifyEmail<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  token: string
): Promise<AuthFlowResult<User>> {
  requireCapability(runtime.config.emailVerification);
  const challenge = await runtime.context.consumeChallenge(
    token,
    "password",
    ["email_verification"]
  );
  const userId = payloadString(challenge.payload, "userId");
  await runtime.config.store.markEmailVerified(userId);
  const user = await runtime.context.users.findById(userId);
  if (!user) throw new AuthError("challenge_expired");
  return authenticated(runtime, user);
}

export async function resendVerification<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  emailInput: string
): Promise<void> {
  requireCapability(runtime.config.emailVerification);
  const email = normaliseEmailInput(emailInput, runtime.normaliseEmail);
  const account = await runtime.config.store.findByEmail(email);
  if (!account || account.emailVerified) return;
  await issueEmailVerification(runtime, account.user);
}

export async function requestPasswordReset<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  emailInput: string
): Promise<void> {
  const capability = requireCapability(runtime.config.passwordReset);
  const email = normaliseEmailInput(emailInput, runtime.normaliseEmail);
  const account = await runtime.config.store.findByEmail(email);
  if (!account) {
    await runtime.config.hasher.hash("password-reset-timing-padding");
    return;
  }
  const issued = await runtime.context.issueChallenge(
    "password",
    "password_reset",
    { userId: account.user.id }
  );
  await capability.send({
    user: account.user,
    token: issued.token,
    expiresAt: issued.expiresAt,
  });
}

export async function resetPassword<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  input: { readonly token: string; readonly newPassword: string }
): Promise<void> {
  requireCapability(runtime.config.passwordReset);
  validatePasswordInput(
    { email: "password-reset@example.invalid", password: input.newPassword },
    runtime.policy
  );
  const challenge = await runtime.context.consumeChallenge(
    input.token,
    "password",
    ["password_reset"]
  );
  const userId = payloadString(challenge.payload, "userId");
  const passwordHash = await runtime.config.hasher.hash(input.newPassword);
  await runtime.config.store.updatePassword(userId, passwordHash);
  const user = await runtime.context.users.findById(userId);
  if (user) await runtime.config.onPasswordChanged?.(user);
}

export async function changePassword<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  input: {
    readonly userId: string;
    readonly currentPassword: string;
    readonly newPassword: string;
  }
): Promise<void> {
  validateCredentialInput({
    email: "credential@example.invalid",
    password: input.currentPassword,
  });
  const account = await runtime.config.store.findByUserId(input.userId);
  if (
    !account ||
    !(await runtime.config.hasher.verify(
      input.currentPassword,
      account.passwordHash
    ))
  ) {
    throw new AuthError("invalid_credentials");
  }
  validatePasswordInput(
    { email: account.user.email, password: input.newPassword },
    runtime.policy
  );
  const passwordHash = await runtime.config.hasher.hash(input.newPassword);
  await runtime.config.store.updatePassword(input.userId, passwordHash);
  await runtime.config.onPasswordChanged?.(account.user);
}

async function issueEmailVerification<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  user: User
): Promise<AuthFlowResult<User>> {
  const capability = requireCapability(runtime.config.emailVerification);
  const issued = await runtime.context.issueChallenge(
    "password",
    "email_verification",
    { userId: user.id }
  );
  await capability.send({
    user,
    token: issued.token,
    expiresAt: issued.expiresAt,
  });
  return {
    status: "email_verification_required",
    challenge: {
      kind: "email_verification",
      continuationToken: issued.token,
      expiresAt: issued.expiresAt,
      parameters: { email: user.email },
    },
  };
}

async function authenticated<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  user: User
): Promise<AuthFlowResult<User>> {
  const issued = await runtime.context.issueSession(user.id);
  return {
    status: "authenticated",
    session: {
      user,
      token: issued.token,
      expiresAt: issued.expiresAt,
    },
  };
}

async function verifiedPasswordAccount<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  email: string,
  password: string
) {
  const account = await runtime.config.store.findByEmail(email);
  if (!account) {
    await runtime.config.hasher.hash(password);
    throw new AuthError("invalid_credentials");
  }
  if (!(await runtime.config.hasher.verify(password, account.passwordHash))) {
    throw new AuthError("invalid_credentials");
  }
  return account;
}

function reportFailure<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  operation: string,
  startedAt: number,
  cause: unknown
): void {
  report(
    runtime,
    operation,
    cause instanceof AuthError ? "rejected" : "error",
    startedAt,
    cause instanceof AuthError ? cause.code : "storage_error"
  );
}

function report<User extends AuthUser>(
  runtime: PasswordRuntime<User>,
  operation: string,
  result: "success" | "rejected" | "error",
  startedAt: number,
  code?: string
): void {
  runtime.context.report({
    operation,
    provider: "password",
    result,
    ...(code ? { code } : {}),
    startedAt,
  });
}

function payloadString(
  payload: Readonly<Record<string, unknown>>,
  field: string
): string {
  const value = payload[field];
  if (typeof value !== "string") throw new AuthError("challenge_mismatch");
  return value;
}

function requireCapability<T>(value: T | undefined): T {
  if (!value) throw new AuthError("unsupported_operation");
  return value;
}

function safeFailure(cause: unknown): AuthError {
  if (cause instanceof AuthError) return cause;
  return new AuthError("storage_error", undefined, {
    cause,
    retryable: true,
  });
}
