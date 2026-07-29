import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const figmaDefinition = defineOAuthProvider({
    name: "figma",
    authorizationEndpoint: "https://www.figma.com/oauth",
    tokenEndpoint: "https://api.figma.com/v1/oauth/token",
    pkce: false,
    clientAuthentication: "basic",
});

export type FigmaOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createFigmaAuth<User extends AuthUser>(
  options: FigmaOptions<User>
): AuthPlugin<"figma", OAuthOperations<User>, User> {
  return createOAuthProvider(figmaDefinition, {
    ...options,
  });
}
