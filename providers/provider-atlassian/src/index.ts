import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const atlassianDefinition = defineOAuthProvider({
    name: "atlassian",
    authorizationEndpoint: "https://auth.atlassian.com/authorize",
    tokenEndpoint: "https://auth.atlassian.com/oauth/token",
    pkce: false,
    clientAuthentication: "body",
    authorizationParameters: {"audience":"api.atlassian.com","prompt":"consent"},
});

export type AtlassianOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createAtlassianAuth<User extends AuthUser>(
  options: AtlassianOptions<User>
): AuthPlugin<"atlassian", OAuthOperations<User>, User> {
  return createOAuthProvider(atlassianDefinition, {
    ...options,
  });
}
