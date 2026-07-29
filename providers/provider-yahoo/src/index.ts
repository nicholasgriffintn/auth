import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const yahooDefinition = defineOAuthProvider({
    name: "yahoo",
    authorizationEndpoint: "https://api.login.yahoo.com/oauth2/request_auth",
    tokenEndpoint: "https://api.login.yahoo.com/oauth2/get_token",
    pkce: false,
    clientAuthentication: "basic",
});

export type YahooOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createYahooAuth<User extends AuthUser>(
  options: YahooOptions<User>
): AuthPlugin<"yahoo", OAuthOperations<User>, User> {
  return createOAuthProvider(yahooDefinition, {
    ...options,
  });
}
