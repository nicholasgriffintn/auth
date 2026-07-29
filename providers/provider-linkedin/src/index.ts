import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const linkedInDefinition = defineOAuthProvider({
    name: "linkedin",
    authorizationEndpoint: "https://www.linkedin.com/oauth/v2/authorization",
    tokenEndpoint: "https://www.linkedin.com/oauth/v2/accessToken",
    pkce: false,
    clientAuthentication: "body",
});

export type LinkedInOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createLinkedInAuth<User extends AuthUser>(
  options: LinkedInOptions<User>
): AuthPlugin<"linkedin", OAuthOperations<User>, User> {
  return createOAuthProvider(linkedInDefinition, {
    ...options,
  });
}
