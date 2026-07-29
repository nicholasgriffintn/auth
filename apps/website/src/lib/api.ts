import { isRecord } from "@ngriffin_uk/auth-core";
import type {
  AuthClientChallenge,
  AuthClientResult,
} from "@ngriffin_uk/auth-react";

import { readJsonResponse } from "./api-response.ts";

export type DemoProviderId = "amazon-cognito" | "github" | "password";
export type DemoOAuthProviderId = Exclude<DemoProviderId, "password">;

export interface DemoProvider {
  readonly id: DemoProviderId;
  readonly label: string;
  readonly configured: boolean;
}

export interface DemoUser {
  readonly id: string;
  readonly email: string;
  readonly displayName: string;
  readonly avatarUrl?: string;
  readonly provider: string;
}

export interface SessionResponse {
  readonly user: DemoUser | null;
  readonly pendingMfa: boolean;
}

export interface DemoSecurityStatus {
  readonly totpConfigured: boolean;
  readonly passkeyCount: number;
}

export async function getDemoProviders(): Promise<readonly DemoProvider[]> {
  const response = await fetch("/api/providers", {
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error("Could not load the provider demos.");
  const body = await readJsonResponse(response);
  if (!isProviders(body)) throw new Error("The provider response was invalid.");
  return body.providers;
}

export async function getDemoSession(): Promise<SessionResponse> {
  const response = await fetch("/api/session", {
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error("Could not load the demo session.");
  const body = await readJsonResponse(response);
  if (!isSession(body)) throw new Error("The session response was invalid.");
  return body;
}

export async function getDemoSecurity(): Promise<DemoSecurityStatus> {
  const response = await fetch("/api/security/status", {
    headers: { Accept: "application/json" },
  });
  const body = await readJsonResponse(response);
  if (!response.ok || !isSecurityStatus(body)) {
    throw new Error("Could not load the demo security settings.");
  }
  return body;
}

export async function executeSecuritySetup(
  route:
    | "totp/start"
    | "totp/verify"
    | "webauthn/start"
    | "webauthn/verify",
  input: Readonly<Record<string, unknown>> = {},
): Promise<AuthClientResult<DemoUser>> {
  const response = await fetch(`/api/security/${route}`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(input),
  });
  const body = await readJsonResponse(response);
  if (!response.ok) throw new Error(securityErrorMessage(body));
  if (!isAuthClientResult(body)) {
    throw new Error("The security setup response was invalid.");
  }
  return body;
}

export async function executeMfaVerification(
  factor: "totp" | "webauthn",
  input: Readonly<Record<string, unknown>>,
): Promise<AuthClientResult<DemoUser>> {
  const response = await fetch(`/api/mfa/${factor}/verify`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(input),
  });
  const body = await readJsonResponse(response);
  if (!response.ok) throw new Error(mfaErrorMessage(body));
  if (!isAuthClientResult(body) || body.status !== "authenticated") {
    throw new Error("The MFA response was invalid.");
  }
  return body;
}

export async function resumePendingMfa(): Promise<AuthClientResult<DemoUser>> {
  const response = await fetch("/api/mfa/pending", {
    method: "POST",
    headers: { Accept: "application/json" },
  });
  const body = await readJsonResponse(response);
  if (!response.ok) throw new Error(mfaErrorMessage(body));
  if (!isAuthClientResult(body)) {
    throw new Error("The pending MFA response was invalid.");
  }
  return body;
}

export async function signOutDemo(): Promise<void> {
  const response = await fetch("/api/session/logout", {
    method: "POST",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error("Could not end the demo session.");
}

export async function authenticateWithPassword(
  action: "sign-in" | "sign-up",
  input: { readonly email: string; readonly password: string },
): Promise<AuthClientResult<DemoUser>> {
  const response = await fetch(`/api/password/${action}`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(input),
  });
  const body = await readJsonResponse(response);
  if (!response.ok) {
    throw new Error(passwordErrorMessage(body));
  }
  if (!isAuthClientResult(body)) {
    throw new Error("The authentication response was invalid.");
  }
  return body;
}

function isProviders(
  value: unknown,
): value is { readonly providers: readonly DemoProvider[] } {
  if (!isRecord(value) || !Array.isArray(value.providers)) return false;
  return value.providers.every(
    (provider) =>
      isRecord(provider) &&
      (provider.id === "amazon-cognito" ||
        provider.id === "github" ||
        provider.id === "password") &&
      typeof provider.label === "string" &&
      typeof provider.configured === "boolean",
  );
}

function passwordErrorMessage(value: unknown): string {
  if (!isRecord(value) || typeof value.error !== "string") {
    return "Authentication could not be completed.";
  }
  if (value.error === "email_in_use") {
    return "An account already exists for this email address.";
  }
  if (value.error === "invalid_credentials") {
    return "The email address or password is incorrect.";
  }
  if (value.error === "rate_limited") {
    return "Too many attempts. Try again in a minute.";
  }
  if (value.error === "storage_error") {
    return "Authentication is temporarily unavailable. Try again.";
  }
  if (value.error === "invalid_input") {
    return "Enter a valid email address and a password of at least 8 characters.";
  }
  return "Authentication could not be completed.";
}

function isSession(value: unknown): value is SessionResponse {
  if (!isRecord(value) || typeof value.pendingMfa !== "boolean") return false;
  if (value.user === null) return true;
  return isDemoUser(value.user);
}

function isDemoUser(value: unknown): value is DemoUser {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.email === "string" &&
    typeof value.displayName === "string" &&
    typeof value.provider === "string" &&
    (value.avatarUrl === undefined || typeof value.avatarUrl === "string")
  );
}

function isSecurityStatus(value: unknown): value is DemoSecurityStatus {
  return (
    isRecord(value) &&
    typeof value.totpConfigured === "boolean" &&
    Number.isSafeInteger(value.passkeyCount) &&
    Number(value.passkeyCount) >= 0
  );
}

function isAuthClientResult(
  value: unknown,
): value is AuthClientResult<DemoUser> {
  if (!isRecord(value) || typeof value.status !== "string") return false;
  if (value.status === "authenticated") {
    return isDemoUser(value.user);
  }
  return isAuthChallenge(value.challenge);
}

function isAuthChallenge(value: unknown): value is AuthClientChallenge {
  if (
    !isRecord(value) ||
    !isChallengeKind(value.kind) ||
    typeof value.continuationToken !== "string" ||
    typeof value.expiresAt !== "string"
  ) {
    return false;
  }
  if (value.parameters === undefined) return true;
  if (!isRecord(value.parameters)) return false;
  return Object.values(value.parameters).every(
    (parameter) =>
      typeof parameter === "string" ||
      (Array.isArray(parameter) &&
        parameter.every((item) => typeof item === "string")),
  );
}

function isChallengeKind(value: unknown): value is AuthClientChallenge["kind"] {
  return (
    typeof value === "string" &&
    [
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
    ].includes(value)
  );
}

function securityErrorMessage(value: unknown): string {
  if (!isRecord(value) || typeof value.error !== "string") {
    return "Security setup could not be completed.";
  }
  if (value.error === "session_expired") {
    return "Your session expired. Sign in again.";
  }
  if (
    value.error === "challenge_expired" ||
    value.error === "challenge_mismatch"
  ) {
    return "This setup attempt expired. Start again.";
  }
  if (value.error === "invalid_credentials") {
    return "The verification response was not accepted.";
  }
  if (value.error === "rate_limited") {
    return "Too many attempts. Try again in a minute.";
  }
  return "Security setup could not be completed.";
}

function mfaErrorMessage(value: unknown): string {
  if (!isRecord(value) || typeof value.error !== "string") {
    return "Security verification could not be completed.";
  }
  if (
    value.error === "challenge_expired" ||
    value.error === "challenge_mismatch"
  ) {
    return "This sign-in attempt expired. Sign in again.";
  }
  if (value.error === "invalid_credentials") {
    return "The passkey, authenticator code, or recovery code was not accepted.";
  }
  if (value.error === "rate_limited") {
    return "Too many attempts. Try again in a minute.";
  }
  return "Security verification could not be completed.";
}
