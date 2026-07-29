import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const battleNetDefinition = defineOAuthProvider({
    name: "battlenet",
    authorizationEndpoint: "https://oauth.battle.net/authorize",
    tokenEndpoint: "https://oauth.battle.net/token",
    pkce: false,
    clientAuthentication: "body",
});

export type BattleNetOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createBattleNetAuth<User extends AuthUser>(
  options: BattleNetOptions<User>
): AuthPlugin<"battlenet", OAuthOperations<User>, User> {
  return createOAuthProvider(battleNetDefinition, {
    ...options,
  });
}
