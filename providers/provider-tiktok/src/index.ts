import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const tikTokDefinition = defineOAuthProvider({
    name: "tiktok",
    authorizationEndpoint: "https://www.tiktok.com/v2/auth/authorize",
    tokenEndpoint: "https://open.tiktokapis.com/v2/oauth/token/",
    revocationEndpoint: "https://open.tiktokapis.com/v2/oauth/revoke/",
    pkce: true,
    clientAuthentication: "body",
    clientIdParameter: "client_key",
    scopeSeparator: ",",
});

export type TikTokOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createTikTokAuth<User extends AuthUser>(
  options: TikTokOptions<User>
): AuthPlugin<"tiktok", OAuthOperations<User>, User> {
  return createOAuthProvider(tikTokDefinition, {
    ...options,
  });
}
