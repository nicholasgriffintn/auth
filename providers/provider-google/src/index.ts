import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const googleDefinition = defineOAuthProvider({
    name: "google",
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    revocationEndpoint: "https://oauth2.googleapis.com/revoke",
    pkce: true,
    clientAuthentication: "basic",
});

export type GoogleOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createGoogleAuth<User extends AuthUser>(
  options: GoogleOptions<User>
): AuthPlugin<"google", OAuthOperations<User>, User> {
  return createOAuthProvider(googleDefinition, {
    ...options,
  });
}
