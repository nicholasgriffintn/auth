import {
  AuthError,
  isRecord,
  type AuthUser,
} from "@ngriffin_uk/auth-core";
import type { JwtClaims } from "@ngriffin_uk/auth-jwt";

import type {
  AmazonCognitoDirectOptions,
  CognitoAuthenticationResult,
} from "./direct-types.js";

export const MAX_PARAMETER_COUNT = 64;
export const MAX_PARAMETER_LENGTH = 131_072;

export function optionalAuthenticationResult(
  value: unknown
): CognitoAuthenticationResult | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new AuthError("provider_error");
  const expiresIn = value["ExpiresIn"];
  if (
    expiresIn !== undefined &&
    (!Number.isSafeInteger(expiresIn) ||
      Number(expiresIn) <= 0 ||
      Number(expiresIn) > 7 * 24 * 60 * 60)
  ) {
    throw new AuthError("provider_error");
  }
  return {
    ...withOptional("AccessToken", optionalString(value, "AccessToken")),
    ...withOptional("IdToken", optionalString(value, "IdToken")),
    ...withOptional("RefreshToken", optionalString(value, "RefreshToken")),
    ...withOptional("TokenType", optionalString(value, "TokenType")),
    ...(typeof expiresIn === "number"
      ? { ExpiresIn: expiresIn }
      : {}),
  };
}

export function optionalString(
  value: Readonly<Record<string, unknown>>,
  field: string
): string | undefined {
  const item = value[field];
  if (item === undefined) return undefined;
  if (
    typeof item !== "string" ||
    item.length > MAX_PARAMETER_LENGTH
  ) {
    throw new AuthError("provider_error");
  }
  return item;
}

export function requiredString(
  value: Readonly<Record<string, unknown>>,
  field: string
): string {
  const item = optionalString(value, field);
  if (!item) throw new AuthError("provider_error");
  return item;
}

export function optionalStringMap(
  value: unknown
): Readonly<Record<string, string>> | undefined {
  if (value === undefined) return undefined;
  if (!isCognitoStringMap(value)) {
    throw new AuthError("provider_error");
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, String(item)])
  );
}

export function optionalStringArray(
  value: unknown
): readonly string[] | undefined {
  if (value === undefined) return undefined;
  if (
    !Array.isArray(value) ||
    value.length > MAX_PARAMETER_COUNT ||
    value.some(
      (item) =>
        typeof item !== "string" ||
        !item ||
        item.length > MAX_PARAMETER_LENGTH
    )
  ) {
    throw new AuthError("provider_error");
  }
  return value;
}

export function payloadString(
  payload: Readonly<Record<string, unknown>>,
  field: string
): string {
  const value = payload[field];
  if (typeof value !== "string") throw new AuthError("challenge_mismatch");
  return value;
}

export function validateConfig<User extends AuthUser>(
  config: AmazonCognitoDirectOptions<User>
): void {
  if (
    !/^[a-z]{2}(?:-gov)?-[a-z]+-\d_[A-Za-z0-9]+$/u.test(config.userPoolId) ||
    !config.userPoolId.startsWith(`${config.region}_`)
  ) {
    throw new TypeError("Amazon Cognito user-pool ID is invalid.");
  }
  if (
    config.clientMetadata !== undefined &&
    !isCognitoStringMap(config.clientMetadata)
  ) {
    throw new TypeError("Amazon Cognito client metadata is invalid.");
  }
}

export function validateUsername(value: string): void {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > 128
  ) {
    throw new AuthError("invalid_input");
  }
}

export function validatePassword(value: string): void {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > 256
  ) {
    throw new AuthError("invalid_input");
  }
}

export function validateCode(value: string): void {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9-]{1,2048}$/u.test(value)
  ) {
    throw new AuthError("invalid_input");
  }
}

export function validateResponse(value: string): void {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > MAX_PARAMETER_LENGTH
  ) {
    throw new AuthError("invalid_input");
  }
}

export function validateToken(value: string): void {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > MAX_PARAMETER_LENGTH
  ) {
    throw new AuthError("invalid_input");
  }
}

export function validateMfaSetupLabel(value: string): void {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > 128
  ) {
    throw new AuthError("invalid_input");
  }
}

export function validateCognitoStringMap(
  value?: Readonly<Record<string, string>>
): void {
  if (value === undefined) return;
  if (!isCognitoStringMap(value)) {
    throw new AuthError("invalid_input");
  }
}

export function hasRequiredTokenTimes(claims: JwtClaims): boolean {
  return (
    typeof claims.exp === "number" &&
    Number.isFinite(claims.exp) &&
    typeof claims.iat === "number" &&
    Number.isFinite(claims.iat)
  );
}

function withOptional<Key extends string, Value>(
  key: Key,
  value: Value | undefined
): Readonly<Record<string, Value>> {
  return value === undefined ? {} : { [key]: value };
}

function isCognitoStringMap(
  value: unknown
): value is Readonly<Record<string, string>> {
  if (!isRecord(value)) return false;
  const entries = Object.entries(value);
  return (
    entries.length <= MAX_PARAMETER_COUNT &&
    entries.every(
      ([key, item]) =>
        key.length > 0 &&
        key.length <= 256 &&
        typeof item === "string" &&
        item.length <= MAX_PARAMETER_LENGTH
    )
  );
}
