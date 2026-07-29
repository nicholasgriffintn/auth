import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export function keyCloakDefinition(realmUrl: string) {
  return defineOAuthProvider({
    name: "keycloak",
    authorizationEndpoint: joinProviderUrl(realmUrl, "/protocol/openid-connect/auth"),
    tokenEndpoint: joinProviderUrl(realmUrl, "/protocol/openid-connect/token"),
    revocationEndpoint: joinProviderUrl(realmUrl, "/protocol/openid-connect/revoke"),
    pkce: true,
    clientAuthentication: "basic",
  });
}

export type KeyCloakOptions<User extends AuthUser> = OAuthProviderPluginOptions<User>;

export function createKeyCloakAuth<User extends AuthUser>(
  realmUrl: string,
  options: KeyCloakOptions<User>
): AuthPlugin<"keycloak", OAuthOperations<User>, User> {
  return createOAuthProvider(keyCloakDefinition(realmUrl), {
    ...options,
    clientAuthentication:
      options.clientAuthentication ?? (options.clientSecret ? "basic" : "none"),
  });
}
