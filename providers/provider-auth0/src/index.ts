import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export function auth0Definition(domain: string) {
  return defineOAuthProvider({
    name: "auth0",
    authorizationEndpoint: providerDomainUrl(domain, "/authorize"),
    tokenEndpoint: providerDomainUrl(domain, "/oauth/token"),
    revocationEndpoint: providerDomainUrl(domain, "/oauth/revoke"),
    pkce: true,
    clientAuthentication: "basic",
  });
}

export type Auth0Options<User extends AuthUser> = OAuthProviderPluginOptions<User>;

export function createAuth0Auth<User extends AuthUser>(
  domain: string,
  options: Auth0Options<User>
): AuthPlugin<"auth0", OAuthOperations<User>, User> {
  return createOAuthProvider(auth0Definition(domain), {
    ...options,
    clientAuthentication:
      options.clientAuthentication ?? (options.clientSecret ? "basic" : "none"),
  });
}
