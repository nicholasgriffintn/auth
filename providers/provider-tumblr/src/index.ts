import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const tumblrDefinition = defineOAuthProvider({
    name: "tumblr",
    authorizationEndpoint: "https://www.tumblr.com/oauth2/authorize",
    tokenEndpoint: "https://api.tumblr.com/v2/oauth2/token",
    pkce: false,
    clientAuthentication: "basic",
});

export type TumblrOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createTumblrAuth<User extends AuthUser>(
  options: TumblrOptions<User>
): AuthPlugin<"tumblr", OAuthOperations<User>, User> {
  return createOAuthProvider(tumblrDefinition, {
    ...options,
  });
}
