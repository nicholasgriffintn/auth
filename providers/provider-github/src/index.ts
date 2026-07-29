import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const gitHubDefinition = defineOAuthProvider({
    name: "github",
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    pkce: true,
    clientAuthentication: "basic",
});

export type GitHubOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createGitHubAuth<User extends AuthUser>(
  options: GitHubOptions<User>
): AuthPlugin<"github", OAuthOperations<User>, User> {
  return createOAuthProvider(gitHubDefinition, {
    ...options,
  });
}
