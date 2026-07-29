import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export function gitLabDefinition(baseUrl: string) {
  return defineOAuthProvider({
    name: "gitlab",
    authorizationEndpoint: joinProviderUrl(baseUrl, "/oauth/authorize"),
    tokenEndpoint: joinProviderUrl(baseUrl, "/oauth/token"),
    revocationEndpoint: joinProviderUrl(baseUrl, "/oauth/revoke"),
    pkce: false,
    clientAuthentication: "basic",
  });
}

export type GitLabOptions<User extends AuthUser> = OAuthProviderPluginOptions<User>;

export function createGitLabAuth<User extends AuthUser>(
  baseUrl: string,
  options: GitLabOptions<User>
): AuthPlugin<"gitlab", OAuthOperations<User>, User> {
  return createOAuthProvider(gitLabDefinition(baseUrl), {
    ...options,
    clientAuthentication:
      options.clientAuthentication ?? (options.clientSecret ? "basic" : "none"),
  });
}
