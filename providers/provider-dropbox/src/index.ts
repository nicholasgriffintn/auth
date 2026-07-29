import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const dropboxDefinition = defineOAuthProvider({
    name: "dropbox",
    authorizationEndpoint: "https://www.dropbox.com/oauth2/authorize",
    tokenEndpoint: "https://api.dropboxapi.com/oauth2/token",
    revocationEndpoint: "https://api.dropboxapi.com/2/auth/token/revoke",
    pkce: false,
    clientAuthentication: "basic",
});

export type DropboxOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createDropboxAuth<User extends AuthUser>(
  options: DropboxOptions<User>
): AuthPlugin<"dropbox", OAuthOperations<User>, User> {
  return createOAuthProvider(dropboxDefinition, {
    ...options,
  });
}
