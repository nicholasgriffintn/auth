import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const notionDefinition = defineOAuthProvider({
    name: "notion",
    authorizationEndpoint: "https://api.notion.com/v1/oauth/authorize",
    tokenEndpoint: "https://api.notion.com/v1/oauth/token",
    pkce: false,
    clientAuthentication: "basic",
    authorizationParameters: {"owner":"user"},
});

export type NotionOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createNotionAuth<User extends AuthUser>(
  options: NotionOptions<User>
): AuthPlugin<"notion", OAuthOperations<User>, User> {
  return createOAuthProvider(notionDefinition, {
    ...options,
  });
}
