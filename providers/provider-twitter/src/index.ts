import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const twitterDefinition = defineOAuthProvider({
    name: "twitter",
    authorizationEndpoint: "https://twitter.com/i/oauth2/authorize",
    tokenEndpoint: "https://api.twitter.com/2/oauth2/token",
    revocationEndpoint: "https://api.twitter.com/2/oauth2/revoke",
    pkce: true,
    clientAuthentication: "basic",
});

export type TwitterOptions<User extends AuthUser> = OAuthProviderPluginOptions<User>;

export function createTwitterAuth<User extends AuthUser>(
  options: TwitterOptions<User>
): AuthPlugin<"twitter", OAuthOperations<User>, User> {
  return createOAuthProvider(twitterDefinition, {
    ...options,
    clientAuthentication:
      options.clientAuthentication ?? (options.clientSecret ? "basic" : "none"),
  });
}
