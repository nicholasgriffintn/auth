import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export function giteaDefinition(baseUrl: string) {
  return defineOAuthProvider({
    name: "gitea",
    authorizationEndpoint: joinProviderUrl(baseUrl, "/login/oauth/authorize"),
    tokenEndpoint: joinProviderUrl(baseUrl, "/login/oauth/access_token"),
    pkce: true,
    clientAuthentication: "basic",
  });
}

export type GiteaOptions<User extends AuthUser> = OAuthProviderPluginOptions<User>;

export function createGiteaAuth<User extends AuthUser>(
  baseUrl: string,
  options: GiteaOptions<User>
): AuthPlugin<"gitea", OAuthOperations<User>, User> {
  return createOAuthProvider(giteaDefinition(baseUrl), {
    ...options,
    clientAuthentication:
      options.clientAuthentication ?? (options.clientSecret ? "basic" : "none"),
  });
}
