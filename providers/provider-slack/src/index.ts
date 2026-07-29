import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const slackDefinition = defineOAuthProvider({
    name: "slack",
    authorizationEndpoint: "https://slack.com/openid/connect/authorize",
    tokenEndpoint: "https://slack.com/api/openid.connect.token",
    pkce: false,
    clientAuthentication: "basic",
});

export type SlackOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createSlackAuth<User extends AuthUser>(
  options: SlackOptions<User>
): AuthPlugin<"slack", OAuthOperations<User>, User> {
  return createOAuthProvider(slackDefinition, {
    ...options,
  });
}
