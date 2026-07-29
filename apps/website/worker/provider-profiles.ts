import { AuthError, type ExternalIdentity } from "@ngriffin_uk/auth-core";
import type { OAuthTokenSet } from "@ngriffin_uk/auth-oauth2";
import {
  readResponseText,
  requestWithTimeout,
} from "@ngriffin_uk/auth-request";

import type { DemoProviderId } from "./types";

const PROFILE_TIMEOUT_MS = 8_000;
const MAX_PROFILE_BYTES = 64 * 1_024;
const MAX_IDENTIFIER_LENGTH = 256;
const MAX_PROFILE_STRING_LENGTH = 2_048;

export async function resolveProviderIdentity(
  provider: DemoProviderId,
  tokens: OAuthTokenSet,
  request: typeof fetch = globalThis.fetch,
): Promise<ExternalIdentity> {
  if (provider === "github") {
    return resolveGitHubIdentity(tokens.accessToken, request);
  }
  if (provider === "google") {
    return resolveGoogleIdentity(tokens.accessToken, request);
  }
  return resolveDiscordIdentity(tokens.accessToken, request);
}

async function resolveGitHubIdentity(
  accessToken: string,
  request: typeof fetch,
): Promise<ExternalIdentity> {
  const profile = await requestJsonObject(
    request,
    "https://api.github.com/user",
    accessToken,
    { "User-Agent": "auth.nicholasgriffin.dev" },
  );
  const providerSubject = requiredIdentifier(profile.id, "GitHub");
  let email = optionalString(profile.email, 320);
  let emailVerified: boolean | undefined;

  if (!email) {
    const emails = await requestJsonArray(
      request,
      "https://api.github.com/user/emails",
      accessToken,
      { "User-Agent": "auth.nicholasgriffin.dev" },
    );
    const selected =
      emails.find(
        (candidate) =>
          candidate.primary === true &&
          candidate.verified === true &&
          optionalString(candidate.email, 320),
      ) ??
      emails.find(
        (candidate) =>
          candidate.verified === true &&
          optionalString(candidate.email, 320),
      );
    email = selected ? optionalString(selected.email, 320) : undefined;
    emailVerified = selected?.verified === true;
  }

  return {
    provider: "github",
    providerSubject,
    ...(email ? { email } : {}),
    ...(emailVerified === undefined ? {} : { emailVerified }),
    claims: compactClaims(profile, [
      "id",
      "login",
      "name",
      "avatar_url",
    ]),
  };
}

async function resolveGoogleIdentity(
  accessToken: string,
  request: typeof fetch,
): Promise<ExternalIdentity> {
  const profile = await requestJsonObject(
    request,
    "https://openidconnect.googleapis.com/v1/userinfo",
    accessToken,
  );
  const email = optionalString(profile.email, 320);
  return {
    provider: "google",
    providerSubject: requiredIdentifier(profile.sub, "Google"),
    ...(email ? { email } : {}),
    ...(typeof profile.email_verified === "boolean"
      ? { emailVerified: profile.email_verified }
      : {}),
    claims: compactClaims(profile, [
      "sub",
      "name",
      "picture",
    ]),
  };
}

async function resolveDiscordIdentity(
  accessToken: string,
  request: typeof fetch,
): Promise<ExternalIdentity> {
  const profile = await requestJsonObject(
    request,
    "https://discord.com/api/v10/users/@me",
    accessToken,
  );
  const email = optionalString(profile.email, 320);
  const avatarHash = optionalString(profile.avatar, 256);
  const providerSubject = requiredIdentifier(profile.id, "Discord");
  const claims = avatarHash
    ? {
        ...compactClaims(profile, ["id", "username", "global_name"]),
        avatar_url: `https://cdn.discordapp.com/avatars/${encodeURIComponent(providerSubject)}/${encodeURIComponent(avatarHash)}.png`,
      }
    : compactClaims(profile, ["id", "username", "global_name"]);
  return {
    provider: "discord",
    providerSubject,
    ...(email ? { email } : {}),
    ...(typeof profile.verified === "boolean"
      ? { emailVerified: profile.verified }
      : {}),
    claims,
  };
}

async function requestJsonObject(
  request: typeof fetch,
  url: string,
  accessToken: string,
  extraHeaders: Readonly<Record<string, string>> = {},
): Promise<Readonly<Record<string, unknown>>> {
  const value = await requestJson(request, url, accessToken, extraHeaders);
  if (!isRecord(value)) throw providerProfileError();
  return value;
}

async function requestJsonArray(
  request: typeof fetch,
  url: string,
  accessToken: string,
  extraHeaders: Readonly<Record<string, string>> = {},
): Promise<readonly Readonly<Record<string, unknown>>[]> {
  const value = await requestJson(request, url, accessToken, extraHeaders);
  if (!Array.isArray(value) || !value.every(isRecord)) {
    throw providerProfileError();
  }
  return value;
}

async function requestJson(
  request: typeof fetch,
  url: string,
  accessToken: string,
  extraHeaders: Readonly<Record<string, string>>,
): Promise<unknown> {
  let response: Response;
  try {
    response = await requestWithTimeout(
      request,
      url,
      {
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${accessToken}`,
          ...extraHeaders,
        },
        redirect: "error",
      },
      PROFILE_TIMEOUT_MS,
    );
  } catch (cause) {
    throw providerProfileError(cause);
  }
  if (!response.ok) throw providerProfileError();

  try {
    return JSON.parse(await readResponseText(response, MAX_PROFILE_BYTES));
  } catch (cause) {
    throw providerProfileError(cause);
  }
}

function requiredIdentifier(value: unknown, provider: string): string {
  if (typeof value === "string") {
    const identifier = value.trim();
    if (
      identifier &&
      identifier.length <= MAX_IDENTIFIER_LENGTH &&
      !/[\u0000-\u001F\u007F]/u.test(identifier)
    ) {
      return identifier;
    }
  }
  if (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  ) {
    return String(value);
  }
  throw new AuthError(
    "provider_error",
    `${provider} returned an invalid identity.`,
  );
}

function optionalString(
  value: unknown,
  maxLength = MAX_PROFILE_STRING_LENGTH,
): string | undefined {
  if (typeof value !== "string") return undefined;
  const result = value.trim();
  return result && result.length <= maxLength ? result : undefined;
}

function compactClaims(
  source: Readonly<Record<string, unknown>>,
  keys: readonly string[],
): Readonly<Record<string, unknown>> {
  return Object.fromEntries(
    keys.flatMap((key) => {
      const value = compactClaimValue(source[key]);
      return value === undefined ? [] : [[key, value]];
    }),
  );
}

function compactClaimValue(
  value: unknown,
): string | number | boolean | undefined {
  if (typeof value === "string") {
    return optionalString(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) return value;
  return typeof value === "boolean" ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function providerProfileError(cause?: unknown): AuthError {
  return new AuthError("provider_error", undefined, {
    ...(cause === undefined ? {} : { cause }),
    retryable: true,
  });
}
