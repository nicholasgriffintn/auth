import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const twitchDefinition = defineOAuthProvider({
    name: "twitch",
    authorizationEndpoint: "https://id.twitch.tv/oauth2/authorize",
    tokenEndpoint: "https://id.twitch.tv/oauth2/token",
    pkce: false,
    clientAuthentication: "body",
});

export type TwitchOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createTwitchAuth<User extends AuthUser>(
  options: TwitchOptions<User>
): AuthPlugin<"twitch", OAuthOperations<User>, User> {
  return createOAuthProvider(twitchDefinition, {
    ...options,
  });
}
