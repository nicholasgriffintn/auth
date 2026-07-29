import {
  AuthError,
  type AuthPlugin,
  type AuthSession,
  type AuthUser,
} from "@ngriffin_uk/auth-core";
import { sha256 } from "@ngriffin_uk/auth-crypto";
import { encodeBase64Url } from "@ngriffin_uk/auth-encoding";
import { verifyJwt, type JwtClaims } from "@ngriffin_uk/auth-jwt";
import { requestWithTimeout } from "@ngriffin_uk/auth-request";

import { readTokenResponse } from "./tokens.js";
import type {
  OAuthOperations,
  OAuthProviderConfig,
  OAuthStateRecord,
  OAuthTokenSet,
  OAuthTokenGrant,
  StartAuthorizationOptions,
} from "./types.js";

const textEncoder = new TextEncoder();
const TOKEN_REQUEST_TIMEOUT_MS = 10_000;
const RESERVED_AUTHORIZATION_PARAMETERS = new Set([
  "client_id",
  "code_challenge",
  "code_challenge_method",
  "nonce",
  "redirect_uri",
  "response_type",
  "scope",
  "state",
]);

export function oauth2Auth<const Name extends string, User extends AuthUser>(
  config: OAuthProviderConfig<Name, User>
): AuthPlugin<Name, OAuthOperations<User>, User> {
  validateConfig(config);
  return {
    name: config.name,
    install(context) {
      const request = config.fetch ?? globalThis.fetch;
      if (!request) {
        throw new AuthError("unsupported_operation", "Fetch is unavailable.");
      }

      return {
        async startAuthorization(options) {
          const now = context.now();
          const state = context.randomToken();
          const codeVerifier =
            config.pkce === false ? undefined : context.randomToken();
          const nonce = config.oidc ? context.randomToken() : undefined;
          const expiresAt = new Date(
            now.getTime() + (config.stateTtlMs ?? 10 * 60 * 1_000)
          );
          const record: OAuthStateRecord = {
            stateHash: await context.hashSecret(state),
            provider: config.name,
            ...(codeVerifier ? { codeVerifier } : {}),
            ...(nonce ? { nonce } : {}),
            ...(config.redirectUri ? { redirectUri: config.redirectUri } : {}),
            createdAt: now,
            expiresAt,
          };
          await config.stateStore.create(record);
          return createAuthorizationUrl(
            config,
            state,
            codeVerifier,
            nonce,
            options
          );
        },

        async completeAuthorization(input) {
          validateCallbackValue(input.state, "state", 4_096);
          validateCallbackValue(input.code, "code", 131_072);
          const record = await consumeState(config, context, input.state);
          const tokens = await exchangeCode(
            config,
            request,
            input.code,
            record,
            context.now()
          );
          const claims = await validateIdToken(
            config,
            tokens,
            record,
            context.now
          );
          const identity = await config.resolveIdentity(tokens, claims);
          if (identity.provider !== config.name) {
            throw new AuthError("identity_conflict");
          }
          if (!context.identities) {
            throw new AuthError(
              "unsupported_operation",
              "An identity store is required for OAuth authentication."
            );
          }
          const user = await context.identities.resolve(identity);
          const issued = await context.issueSession(user.id);
          const session: AuthSession<User> = {
            user,
            token: issued.token,
            expiresAt: issued.expiresAt,
          };
          return { status: "authenticated", session };
        },

        refresh(refreshToken, scopes) {
          validateOperationValue(refreshToken, "refresh token");
          validateScopes(scopes ?? [], config.scopeSeparator ?? " ");
          const body = new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: refreshToken,
          });
          if (scopes?.length) {
            body.set("scope", scopes.join(config.scopeSeparator ?? " "));
          }
          return sendTokenRequest(
            config,
            request,
            body,
            context.now(),
            "refresh_token"
          );
        },

        async revoke(token) {
          if (!config.revocationEndpoint) {
            throw new AuthError("unsupported_operation");
          }
          validateOperationValue(token, "revocation token");
          const body = new URLSearchParams({ token });
          applyTokenParameters(config, body, "revoke");
          let response: Response;
          try {
            response = await requestWithTimeout(
              request,
              config.revocationEndpoint,
              {
                method: "POST",
                headers: await createTokenHeaders(config, body),
                body,
                redirect: "error",
              },
              TOKEN_REQUEST_TIMEOUT_MS
            );
          } catch (cause) {
            throw new AuthError("provider_error", undefined, {
              cause,
              retryable: true,
            });
          }
          if (!response.ok) throw new AuthError("provider_error");
        },
      };
    },
  };
}

async function createAuthorizationUrl<
  Name extends string,
  User extends AuthUser,
>(
  config: OAuthProviderConfig<Name, User>,
  state: string,
  codeVerifier: string | undefined,
  nonce: string | undefined,
  options: StartAuthorizationOptions | undefined
): Promise<URL> {
  const url = new URL(config.authorizationEndpoint);
  const parameters = {
    ...config.authorizationParameters,
    ...options?.authorizationParameters,
  };
  for (const [name, value] of Object.entries(parameters)) {
    if (RESERVED_AUTHORIZATION_PARAMETERS.has(name)) {
      throw new AuthError(
        "invalid_input",
        `Authorization parameter '${name}' is reserved.`
      );
    }
    url.searchParams.set(name, value);
  }
  url.searchParams.set("response_type", "code");
  url.searchParams.set(config.clientIdParameter ?? "client_id", config.clientId);
  if (config.redirectUri) {
    url.searchParams.set("redirect_uri", config.redirectUri);
  }
  url.searchParams.set("state", state);
  if (codeVerifier) {
    url.searchParams.set("code_challenge_method", "S256");
    const challenge = await sha256(textEncoder.encode(codeVerifier));
    url.searchParams.set("code_challenge", encodeBase64Url(challenge));
  }
  if (nonce) url.searchParams.set("nonce", nonce);
  const scopes = options?.scopes ?? config.scopes ?? [];
  validateScopes(scopes, config.scopeSeparator ?? " ");
  if (scopes.length) {
    url.searchParams.set("scope", scopes.join(config.scopeSeparator ?? " "));
  }
  return url;
}

async function consumeState<Name extends string, User extends AuthUser>(
  config: OAuthProviderConfig<Name, User>,
  context: {
    now(): Date;
    hashSecret(secret: string): Promise<string>;
  },
  state: string
): Promise<OAuthStateRecord> {
  const record = await config.stateStore.consumeByStateHash(
    await context.hashSecret(state)
  );
  if (
    !record ||
    !(record.expiresAt instanceof Date) ||
    !Number.isFinite(record.expiresAt.getTime()) ||
    record.provider !== config.name ||
    record.redirectUri !== config.redirectUri ||
    record.expiresAt.getTime() <= context.now().getTime()
  ) {
    throw new AuthError("invalid_callback");
  }
  return record;
}

async function exchangeCode<Name extends string, User extends AuthUser>(
  config: OAuthProviderConfig<Name, User>,
  request: typeof globalThis.fetch,
  code: string,
  state: OAuthStateRecord,
  now: Date
): Promise<OAuthTokenSet> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
  });
  if (state.redirectUri) body.set("redirect_uri", state.redirectUri);
  if (state.codeVerifier) body.set("code_verifier", state.codeVerifier);
  return sendTokenRequest(
    config,
    request,
    body,
    now,
    "authorization_code"
  );
}

async function sendTokenRequest<Name extends string, User extends AuthUser>(
  config: OAuthProviderConfig<Name, User>,
  request: typeof globalThis.fetch,
  body: URLSearchParams,
  now: Date,
  grant: OAuthTokenGrant
): Promise<OAuthTokenSet> {
  applyTokenParameters(config, body, grant);
  let response: Response;
  try {
    response = await requestWithTimeout(
      request,
      config.tokenEndpoint,
      {
        method: "POST",
        headers: await createTokenHeaders(config, body),
        body,
        redirect: "error",
      },
      TOKEN_REQUEST_TIMEOUT_MS
    );
  } catch (cause) {
    throw new AuthError("oauth_exchange_failed", undefined, {
      cause,
      retryable: true,
    });
  }
  return readTokenResponse(response, now, config.tokenResponsePath);
}

async function createTokenHeaders<
  Name extends string,
  User extends AuthUser,
>(
  config: OAuthProviderConfig<Name, User>,
  body: URLSearchParams
): Promise<Headers> {
  const headers = new Headers({
    Accept: "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    ...config.tokenHeaders,
  });
  const method = config.clientAuthentication ?? "basic";
  if (method === "basic") {
    const clientSecret = await resolveClientSecret(config.clientSecret);
    headers.set(
      "Authorization",
      `Basic ${btoa(`${encodeURIComponent(config.clientId)}:${encodeURIComponent(clientSecret)}`)}`
    );
  } else {
    body.set(config.clientIdParameter ?? "client_id", config.clientId);
    if (method === "body") {
      body.set("client_secret", await resolveClientSecret(config.clientSecret));
    }
  }
  return headers;
}

async function resolveClientSecret(
  value: OAuthProviderConfig<string, AuthUser>["clientSecret"]
): Promise<string> {
  const secret = typeof value === "function" ? await value() : value;
  if (!secret) throw new AuthError("invalid_input");
  return secret;
}

function applyTokenParameters<Name extends string, User extends AuthUser>(
  config: OAuthProviderConfig<Name, User>,
  body: URLSearchParams,
  grant: OAuthTokenGrant
): void {
  for (const [name, value] of Object.entries(
    config.tokenParameters?.[grant] ?? {}
  )) {
    if (!body.has(name)) body.set(name, value);
  }
}

async function validateIdToken<Name extends string, User extends AuthUser>(
  config: OAuthProviderConfig<Name, User>,
  tokens: OAuthTokenSet,
  state: OAuthStateRecord,
  clock: () => Date
): Promise<JwtClaims | null> {
  if (!config.oidc) return null;
  if (!tokens.idToken || !state.nonce) throw new AuthError("invalid_callback");
  const claims = await verifyJwt(tokens.idToken, {
    algorithms: config.oidc.algorithms,
    key: config.oidc.key,
    issuer: config.oidc.issuer,
    audience: config.oidc.audience ?? config.clientId,
    clock,
  });
  if (claims.nonce !== state.nonce) throw new AuthError("invalid_callback");
  return claims;
}

function validateConfig<Name extends string, User extends AuthUser>(
  config: OAuthProviderConfig<Name, User>
): void {
  for (const endpoint of [
    config.authorizationEndpoint,
    config.tokenEndpoint,
    config.revocationEndpoint,
  ]) {
    if (!endpoint) continue;
    const url = new URL(endpoint);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.hash
    ) {
      throw new AuthError("invalid_input", "OAuth endpoints must use HTTPS.");
    }
  }
  if (!config.name || !config.clientId) {
    throw new AuthError("invalid_input");
  }
  validateScopes(config.scopes ?? [], config.scopeSeparator ?? " ");
  if (config.oidc && config.oidc.algorithms.length === 0) {
    throw new AuthError(
      "invalid_input",
      "OIDC requires at least one allowed signing algorithm."
    );
  }
  if (
    config.stateTtlMs !== undefined &&
    (!Number.isSafeInteger(config.stateTtlMs) || config.stateTtlMs <= 0)
  ) {
    throw new AuthError(
      "invalid_input",
      "OAuth state lifetime must be a positive integer."
    );
  }
  if (config.redirectUri) {
    const redirectUri = new URL(config.redirectUri);
    const localHttp =
      redirectUri.protocol === "http:" &&
      ["127.0.0.1", "localhost", "[::1]"].includes(redirectUri.hostname);
    if (
      (redirectUri.protocol !== "https:" && !localHttp) ||
      redirectUri.username ||
      redirectUri.password ||
      redirectUri.hash
    ) {
      throw new AuthError("invalid_input", "OAuth redirect URI is invalid.");
    }
  }
}

function validateCallbackValue(
  value: string,
  field: string,
  maxLength: number
): void {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength
  ) {
    throw new AuthError("invalid_callback", `OAuth ${field} is invalid.`);
  }
}

function validateOperationValue(value: string, field: string): void {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 131_072
  ) {
    throw new AuthError("invalid_input", `OAuth ${field} is invalid.`);
  }
}

function validateScopes(
  scopes: readonly string[],
  separator: " " | ","
): void {
  if (
    !Array.isArray(scopes) ||
    scopes.length > 100 ||
    scopes.some(
      (scope) =>
        typeof scope !== "string" ||
        scope.length === 0 ||
        scope.length > 1024 ||
        /\s/u.test(scope) ||
        (separator === "," && scope.includes(","))
    )
  ) {
    throw new AuthError("invalid_input", "OAuth scopes are invalid.");
  }
}
