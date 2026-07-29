import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createRemoteJwksResolver,
  type JwtAlgorithm,
} from "@ngriffin_uk/auth-jwt";

import { discoverOpenIdConfiguration } from "./discovery.js";
import {
  createOAuthProvider,
  defineOAuthProvider,
  type OAuthProviderPluginOptions,
} from "./provider.js";
import type { OAuthOperations } from "./types.js";

export interface DiscoveredOidcProviderOptions<User extends AuthUser>
  extends Omit<OAuthProviderPluginOptions<User>, "oidc"> {
  readonly algorithms: readonly JwtAlgorithm[];
  readonly discoveryTimeoutMs?: number;
  readonly jwksCacheTtlMs?: number;
}

export async function createDiscoveredOidcProvider<
  const Name extends string,
  User extends AuthUser,
>(
  name: Name,
  issuer: string,
  options: DiscoveredOidcProviderOptions<User>
): Promise<AuthPlugin<Name, OAuthOperations<User>, User>> {
  if (options.algorithms.length === 0) {
    throw new TypeError("At least one OIDC signing algorithm must be pinned.");
  }
  const configuration = await discoverOpenIdConfiguration(issuer, {
    ...(options.fetch ? { fetch: options.fetch } : {}),
    ...(options.discoveryTimeoutMs
      ? { timeoutMs: options.discoveryTimeoutMs }
      : {}),
  });
  const advertisedAlgorithms =
    configuration.idTokenSigningAlgorithmsSupported;
  if (
    advertisedAlgorithms.length > 0 &&
    options.algorithms.some(
      (algorithm) => !advertisedAlgorithms.includes(algorithm)
    )
  ) {
    throw new TypeError(
      "Pinned OIDC algorithm is not advertised by the provider."
    );
  }
  if (
    configuration.codeChallengeMethodsSupported.length > 0 &&
    !configuration.codeChallengeMethodsSupported.includes("S256")
  ) {
    throw new TypeError("OIDC provider does not advertise PKCE S256.");
  }

  const {
    algorithms,
    discoveryTimeoutMs: _discoveryTimeoutMs,
    jwksCacheTtlMs,
    ...providerOptions
  } = options;
  const definition = defineOAuthProvider({
    name,
    authorizationEndpoint: configuration.authorizationEndpoint,
    tokenEndpoint: configuration.tokenEndpoint,
    ...(configuration.revocationEndpoint
      ? { revocationEndpoint: configuration.revocationEndpoint }
      : {}),
    pkce: true,
    clientAuthentication:
      options.clientAuthentication ?? (options.clientSecret ? "basic" : "none"),
  });
  return createOAuthProvider(definition, {
    ...providerOptions,
    oidc: {
      issuer: configuration.issuer,
      audience: options.clientId,
      algorithms,
      key: createRemoteJwksResolver({
        url: configuration.jwksUri,
        ...(options.fetch ? { fetch: options.fetch } : {}),
        ...(jwksCacheTtlMs ? { cacheTtlMs: jwksCacheTtlMs } : {}),
      }),
    },
  });
}
