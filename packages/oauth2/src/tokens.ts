import { AuthError } from "@ngriffin_uk/auth-core";
import { readResponseText } from "@ngriffin_uk/auth-request";

import type { OAuthTokenSet } from "./types.js";

const MAX_TOKEN_RESPONSE_BYTES = 1024 * 1024;
const MAX_TOKEN_LIFETIME_SECONDS = 365 * 24 * 60 * 60;

export function parseTokenResponse(
  value: unknown,
  now: Date
): OAuthTokenSet {
  if (!isObject(value)) {
    throw new AuthError("oauth_exchange_failed");
  }
  const accessToken = value.access_token;
  const tokenType = value.token_type;
  if (typeof accessToken !== "string" || typeof tokenType !== "string") {
    throw new AuthError("oauth_exchange_failed");
  }

  const expiresIn = parseExpiresIn(value.expires_in);
  return {
    accessToken,
    tokenType,
    ...(expiresIn === undefined
      ? {}
      : { expiresAt: new Date(now.getTime() + expiresIn * 1_000) }),
    ...(typeof value.refresh_token === "string"
      ? { refreshToken: value.refresh_token }
      : {}),
    ...(typeof value.id_token === "string" ? { idToken: value.id_token } : {}),
    ...(typeof value.scope === "string"
      ? { scopes: value.scope.split(/\s+/u).filter(Boolean) }
      : {}),
    values: value,
  };
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
