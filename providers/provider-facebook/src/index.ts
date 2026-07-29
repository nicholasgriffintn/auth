import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const facebookDefinition = defineOAuthProvider({
    name: "facebook",
    authorizationEndpoint: "https://www.facebook.com/v16.0/dialog/oauth",
    tokenEndpoint: "https://graph.facebook.com/v16.0/oauth/access_token",
    pkce: false,
    clientAuthentication: "body",
});

export type FacebookOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createFacebookAuth<User extends AuthUser>(
  options: FacebookOptions<User>
): AuthPlugin<"facebook", OAuthOperations<User>, User> {
  return createOAuthProvider(facebookDefinition, {
    ...options,
  });
}
