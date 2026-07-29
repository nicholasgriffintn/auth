import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const dribbbleDefinition = defineOAuthProvider({
    name: "dribbble",
    authorizationEndpoint: "https://dribbble.com/oauth/authorize",
    tokenEndpoint: "https://dribbble.com/oauth/token",
    pkce: false,
    clientAuthentication: "body",
});

export type DribbbleOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createDribbbleAuth<User extends AuthUser>(
  options: DribbbleOptions<User>
): AuthPlugin<"dribbble", OAuthOperations<User>, User> {
  return createOAuthProvider(dribbbleDefinition, {
    ...options,
  });
}
