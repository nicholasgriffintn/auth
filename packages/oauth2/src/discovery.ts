import { AuthError } from "@ngriffin_uk/auth-core";
import {
  readResponseText,
  requestWithTimeout,
} from "@ngriffin_uk/auth-request";

const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;

export interface OpenIdConfiguration {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly jwksUri: string;
  readonly revocationEndpoint?: string;
  readonly userinfoEndpoint?: string;
  readonly codeChallengeMethodsSupported: readonly string[];
  readonly idTokenSigningAlgorithmsSupported: readonly string[];
}

export interface DiscoveryOptions {
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
  readonly timeoutMs?: number;
}

export async function discoverOpenIdConfiguration(
  issuer: string,
  options: DiscoveryOptions = {}
): Promise<OpenIdConfiguration> {
  const normalisedIssuer = validateIssuer(issuer);
  const request = options.fetch ?? globalThis.fetch;
  if (!request) {
    throw new AuthError("unsupported_operation", "Fetch is unavailable.");
  }
  const maxResponseBytes = positiveInteger(
    options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    "Discovery response size"
  );
  const timeoutMs = positiveInteger(
    options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    "Discovery timeout"
  );
  const discoveryUrl = new URL(
    `${normalisedIssuer.replace(/\/$/u, "")}/.well-known/openid-configuration`
  );
  let response: Response;
  try {
    response = await requestWithTimeout(
      request,
      discoveryUrl,
      {
        headers: { Accept: "application/json" },
        redirect: "error",
      },
      timeoutMs
    );
  } catch (cause) {
    throw new AuthError("provider_error", undefined, {
      cause,
      retryable: true,
    });
  }
  if (!response.ok) {
    throw new AuthError("provider_error", undefined, { retryable: true });
  }

  let text: string;
  try {
    text = await readResponseText(response, maxResponseBytes);
  } catch (cause) {
    throw new AuthError("provider_error", undefined, { cause });
  }

  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (cause) {
    throw new AuthError("provider_error", undefined, { cause });
  }
  return parseConfiguration(value, normalisedIssuer);
}

function parseConfiguration(
  value: unknown,
  expectedIssuer: string
): OpenIdConfiguration {
  if (!isObject(value) || value.issuer !== expectedIssuer) {
    throw new AuthError("provider_error");
  }
  const authorizationEndpoint = secureEndpoint(value.authorization_endpoint);
  const tokenEndpoint = secureEndpoint(value.token_endpoint);
  const jwksUri = secureEndpoint(value.jwks_uri);
  return {
    issuer: expectedIssuer,
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri,
    ...(value.revocation_endpoint === undefined
      ? {}
      : { revocationEndpoint: secureEndpoint(value.revocation_endpoint) }),
    ...(value.userinfo_endpoint === undefined
      ? {}
      : { userinfoEndpoint: secureEndpoint(value.userinfo_endpoint) }),
    codeChallengeMethodsSupported: stringArray(
      value.code_challenge_methods_supported
    ),
    idTokenSigningAlgorithmsSupported: stringArray(
      value.id_token_signing_alg_values_supported
    ),
  };
}

function validateIssuer(value: string): string {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new AuthError("invalid_input", "OIDC issuer must be an HTTPS URL.");
  }
  return url.href.replace(/\/$/u, "");
}

function secureEndpoint(value: unknown): string {
  if (typeof value !== "string") throw new AuthError("provider_error");
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash
  ) {
    throw new AuthError("provider_error");
  }
  return url.href;
}

function stringArray(value: unknown): readonly string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new AuthError("provider_error");
  }
  return value;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new AuthError("invalid_input", `${label} must be a positive integer.`);
  }
  return value;
}
