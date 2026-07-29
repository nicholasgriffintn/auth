import { AuthError } from "@ngriffin_uk/auth-core";
import { readResponseText } from "@ngriffin_uk/auth-request";

import type { OAuthTokenSet } from "./types.js";

const MAX_TOKEN_RESPONSE_BYTES = 1024 * 1024;
const MAX_TOKEN_LIFETIME_SECONDS = 365 * 24 * 60 * 60;
const MAX_TOKEN_LENGTH = 131_072;
const MAX_TOKEN_TYPE_LENGTH = 128;

export function parseTokenResponse(
  value: unknown,
  now: Date
): OAuthTokenSet {
  if (!isObject(value)) {
    throw new AuthError("oauth_exchange_failed");
  }
  const accessToken = value.access_token;
  const tokenType = value.token_type;
  if (
    !isBoundedString(accessToken, MAX_TOKEN_LENGTH) ||
    !isBoundedString(tokenType, MAX_TOKEN_TYPE_LENGTH)
  ) {
    throw new AuthError("oauth_exchange_failed");
  }

  const expiresIn = parseExpiresIn(value.expires_in);
  const refreshToken = optionalToken(value.refresh_token);
  const idToken = optionalToken(value.id_token);
  const scopes = parseScopes(value.scope);
  const timestamp = now.getTime();
  if (expiresIn !== undefined && !Number.isFinite(timestamp)) {
    throw new AuthError("oauth_exchange_failed");
  }
  const expiresAt =
    expiresIn === undefined
      ? undefined
      : new Date(timestamp + expiresIn * 1_000);
  if (expiresAt && !Number.isFinite(expiresAt.getTime())) {
    throw new AuthError("oauth_exchange_failed");
  }
  return {
    accessToken,
    tokenType,
    ...(expiresAt ? { expiresAt } : {}),
    ...(refreshToken ? { refreshToken } : {}),
    ...(idToken ? { idToken } : {}),
    ...(scopes ? { scopes } : {}),
    values: value,
  };
}

function optionalToken(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (!isBoundedString(value, MAX_TOKEN_LENGTH)) {
    throw new AuthError("oauth_exchange_failed");
  }
  return value;
}

function parseScopes(value: unknown): readonly string[] | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > MAX_TOKEN_LENGTH) {
    throw new AuthError("oauth_exchange_failed");
  }
  const scopes = value.split(/\s+/u).filter(Boolean);
  if (
    scopes.length > 100 ||
    scopes.some((scope) => scope.length > 1_024)
  ) {
    throw new AuthError("oauth_exchange_failed");
  }
  return scopes;
}

function isBoundedString(value: unknown, maxLength: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maxLength
  );
}

export async function readTokenResponse(
  response: Response,
  now: Date,
  responsePath: readonly string[] = []
): Promise<OAuthTokenSet> {
  let body: unknown;
  try {
    const text = await readResponseText(response, MAX_TOKEN_RESPONSE_BYTES);
    const contentType = response.headers.get("Content-Type") ?? "";
    if (contentType.includes("application/x-www-form-urlencoded")) {
      body = Object.fromEntries(new URLSearchParams(text));
    } else {
      body = JSON.parse(text);
    }
  } catch (cause) {
    throw new AuthError("oauth_exchange_failed", undefined, { cause });
  }
  if (!response.ok) {
    throw new AuthError("oauth_exchange_failed");
  }
  return parseTokenResponse(readPath(body, responsePath), now);
}

function parseExpiresIn(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  const parsed =
    typeof value === "number"
      ? value
      : typeof value === "string"
        ? Number(value)
        : Number.NaN;
  if (
    !Number.isSafeInteger(parsed) ||
    parsed < 0 ||
    parsed > MAX_TOKEN_LIFETIME_SECONDS
  ) {
    throw new AuthError("oauth_exchange_failed");
  }
  return parsed;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readPath(value: unknown, path: readonly string[]): unknown {
  let current = value;
  for (const segment of path) {
    if (!isObject(current) || !(segment in current)) {
      throw new AuthError("oauth_exchange_failed");
    }
    current = current[segment];
  }
  return current;
}
