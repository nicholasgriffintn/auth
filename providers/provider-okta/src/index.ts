import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export function oktaDefinition(baseUrl: string) {
  return defineOAuthProvider({
    name: "okta",
    authorizationEndpoint: joinProviderUrl(baseUrl, "/v1/authorize"),
    tokenEndpoint: joinProviderUrl(baseUrl, "/v1/token"),
    revocationEndpoint: joinProviderUrl(baseUrl, "/v1/revoke"),
    pkce: true,
    clientAuthentication: "basic",
  });
}

export type OktaOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createOktaAuth<User extends AuthUser>(
  baseUrl: string,
  options: OktaOptions<User>
): AuthPlugin<"okta", OAuthOperations<User>, User> {
  return createOAuthProvider(oktaDefinition(baseUrl), {
    ...options,
  });
}
