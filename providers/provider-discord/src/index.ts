import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const discordDefinition = defineOAuthProvider({
    name: "discord",
    authorizationEndpoint: "https://discord.com/oauth2/authorize",
    tokenEndpoint: "https://discord.com/api/oauth2/token",
    revocationEndpoint: "https://discord.com/api/oauth2/token/revoke",
    pkce: true,
    clientAuthentication: "basic",
});

export type DiscordOptions<User extends AuthUser> = OAuthProviderPluginOptions<User>;

export function createDiscordAuth<User extends AuthUser>(
  options: DiscordOptions<User>
): AuthPlugin<"discord", OAuthOperations<User>, User> {
  return createOAuthProvider(discordDefinition, {
    ...options,
    clientAuthentication:
      options.clientAuthentication ?? (options.clientSecret ? "basic" : "none"),
  });
}
