import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const vKDefinition = defineOAuthProvider({
    name: "vk",
    authorizationEndpoint: "https://oauth.vk.com/authorize",
    tokenEndpoint: "https://oauth.vk.com/access_token",
    pkce: false,
    clientAuthentication: "body",
});

export type VKOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createVKAuth<User extends AuthUser>(
  options: VKOptions<User>
): AuthPlugin<"vk", OAuthOperations<User>, User> {
  return createOAuthProvider(vKDefinition, {
    ...options,
  });
}
