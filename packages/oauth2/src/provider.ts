import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";

import { oauth2Auth } from "./plugin.js";
import type {
  ClientAuthentication,
  ClientSecretProvider,
  OAuthOperations,
  OAuthProviderConfig,
  OAuthStateStore,
  OAuthTokenGrant,
  OAuthTokenSet,
  OidcConfig,
} from "./types.js";
import type { ExternalIdentity } from "@ngriffin_uk/auth-core";
import type { JwtClaims } from "@ngriffin_uk/auth-jwt";

const PROVIDER_NAME_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const RESERVED_PARAMETERS = new Set([
  "client_id",
  "code_challenge",
  "code_challenge_method",
  "nonce",
  "redirect_uri",
  "response_type",
  "scope",
  "state",
]);

export interface OAuthProviderDefinition<Name extends string> {
  readonly name: Name;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly revocationEndpoint?: string;
  readonly defaultScopes?: readonly string[];
  readonly clientAuthentication?: ClientAuthentication;
  readonly pkce: boolean;
  readonly clientIdParameter?: string;
  readonly scopeSeparator?: " " | ",";
  readonly tokenParameters?: Partial<
    Readonly<Record<OAuthTokenGrant, Readonly<Record<string, string>>>>
  >;
  readonly tokenResponsePath?: readonly string[];
  readonly tokenHeaders?: Readonly<Record<string, string>>;
  readonly authorizationParameters?: Readonly<Record<string, string>>;
}

export interface OAuthProviderPluginOptions<User extends AuthUser> {
  readonly clientId: string;
  readonly clientSecret?: string | ClientSecretProvider;
  readonly clientAuthentication?: ClientAuthentication;
  readonly redirectUri?: string;
  readonly scopes?: readonly string[];
  readonly authorizationParameters?: Readonly<Record<string, string>>;
  readonly stateStore: OAuthStateStore;
  readonly stateTtlMs?: number;
  readonly fetch?: typeof globalThis.fetch;
  readonly oidc?: OidcConfig;
  readonly resolveIdentity: (
    tokens: OAuthTokenSet,
    idTokenClaims: JwtClaims | null
  ) => Promise<ExternalIdentity>;
}

export function defineOAuthProvider<const Name extends string>(
  definition: OAuthProviderDefinition<Name>
): Readonly<OAuthProviderDefinition<Name>> {
  validateOAuthProviderDefinition(definition);
  return Object.freeze({
    ...definition,
    ...(definition.defaultScopes
      ? { defaultScopes: Object.freeze([...definition.defaultScopes]) }
      : {}),
    ...(definition.authorizationParameters
      ? {
          authorizationParameters: Object.freeze({
            ...definition.authorizationParameters,
          }),
        }
      : {}),
  });
}

export function createOAuthProvider<
  const Name extends string,
  User extends AuthUser,
>(
  definition: OAuthProviderDefinition<Name>,
  options: OAuthProviderPluginOptions<User>
): AuthPlugin<Name, OAuthOperations<User>, User> {
  validateOAuthProviderDefinition(definition);
  const config: OAuthProviderConfig<Name, User> = {
    name: definition.name,
    clientId: options.clientId,
    authorizationEndpoint: definition.authorizationEndpoint,
    tokenEndpoint: definition.tokenEndpoint,
    stateStore: options.stateStore,
    resolveIdentity: options.resolveIdentity,
    ...(options.redirectUri !== undefined
      ? { redirectUri: options.redirectUri }
      : {}),
    ...(options.clientSecret !== undefined
      ? { clientSecret: options.clientSecret }
      : {}),
    ...(definition.revocationEndpoint
      ? { revocationEndpoint: definition.revocationEndpoint }
      : {}),
    ...(options.scopes ?? definition.defaultScopes
      ? { scopes: options.scopes ?? definition.defaultScopes }
      : {}),
    ...(options.clientAuthentication ?? definition.clientAuthentication
      ? {
          clientAuthentication:
            options.clientAuthentication ?? definition.clientAuthentication,
        }
      : {}),
    pkce: definition.pkce,
    ...(definition.clientIdParameter
      ? { clientIdParameter: definition.clientIdParameter }
      : {}),
    ...(definition.scopeSeparator
      ? { scopeSeparator: definition.scopeSeparator }
      : {}),
    ...(definition.tokenParameters
      ? { tokenParameters: definition.tokenParameters }
      : {}),
    ...(definition.tokenResponsePath
      ? { tokenResponsePath: definition.tokenResponsePath }
      : {}),
    ...(definition.tokenHeaders
      ? { tokenHeaders: definition.tokenHeaders }
      : {}),
    ...(mergeParameters(
      definition.authorizationParameters,
      options.authorizationParameters
    )),
    ...(options.stateTtlMs !== undefined
      ? { stateTtlMs: options.stateTtlMs }
      : {}),
    ...(options.fetch ? { fetch: options.fetch } : {}),
    ...(options.oidc ? { oidc: options.oidc } : {}),
  };
  return oauth2Auth(config);
}

export function validateOAuthProviderDefinition(
  definition: OAuthProviderDefinition<string>
): void {
  if (!PROVIDER_NAME_PATTERN.test(definition.name)) {
    throw new TypeError("OAuth provider name must be a lowercase slug.");
  }
  for (const endpoint of [
    definition.authorizationEndpoint,
    definition.tokenEndpoint,
    definition.revocationEndpoint,
  ]) {
    if (!endpoint) continue;
    const url = new URL(endpoint);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.hash
    ) {
      throw new TypeError("OAuth provider endpoints must be secure HTTPS URLs.");
    }
  }
  const scopes = definition.defaultScopes ?? [];
  if (
    scopes.some((scope) => !scope || /\s/u.test(scope)) ||
    new Set(scopes).size !== scopes.length
  ) {
    throw new TypeError("OAuth provider scopes must be unique tokens.");
  }
  for (const key of Object.keys(definition.authorizationParameters ?? {})) {
    if (RESERVED_PARAMETERS.has(key)) {
      throw new TypeError(`OAuth parameter '${key}' is reserved.`);
    }
  }
}

export function joinProviderUrl(baseUrl: string, path: string): string {
  const base = new URL(baseUrl);
  if (
    base.protocol !== "https:" ||
    base.username ||
    base.password ||
    base.search ||
    base.hash
  ) {
    throw new TypeError("Provider base URL must be a secure HTTPS URL.");
  }
  const basePath = base.pathname.replace(/\/+$/u, "");
  const suffix = path.replace(/^\/+/u, "");
  base.pathname = `${basePath}/${suffix}`;
  return base.href;
}

export function providerDomainUrl(domain: string, path: string): string {
  if (!domain || /[/@?#]/u.test(domain)) {
    throw new TypeError("Provider domain is invalid.");
  }
  return joinProviderUrl(`https://${domain}`, path);
}

function mergeParameters(
  defaults: Readonly<Record<string, string>> | undefined,
  overrides: Readonly<Record<string, string>> | undefined
): { authorizationParameters?: Readonly<Record<string, string>> } {
  if (!defaults && !overrides) return {};
  return { authorizationParameters: { ...defaults, ...overrides } };
}
