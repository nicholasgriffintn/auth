import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const redditDefinition = defineOAuthProvider({
    name: "reddit",
    authorizationEndpoint: "https://www.reddit.com/api/v1/authorize",
    tokenEndpoint: "https://www.reddit.com/api/v1/access_token",
    pkce: false,
    clientAuthentication: "basic",
});

export type RedditOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createRedditAuth<User extends AuthUser>(
  options: RedditOptions<User>
): AuthPlugin<"reddit", OAuthOperations<User>, User> {
  return createOAuthProvider(redditDefinition, {
    ...options,
  });
}
