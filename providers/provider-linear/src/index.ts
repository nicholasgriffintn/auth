import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const linearDefinition = defineOAuthProvider({
    name: "linear",
    authorizationEndpoint: "https://linear.app/oauth/authorize",
    tokenEndpoint: "https://api.linear.app/oauth/token",
    pkce: false,
    clientAuthentication: "body",
});

export type LinearOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createLinearAuth<User extends AuthUser>(
  options: LinearOptions<User>
): AuthPlugin<"linear", OAuthOperations<User>, User> {
  return createOAuthProvider(linearDefinition, {
    ...options,
  });
}
