import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const bitbucketDefinition = defineOAuthProvider({
    name: "bitbucket",
    authorizationEndpoint: "https://bitbucket.org/site/oauth2/authorize",
    tokenEndpoint: "https://bitbucket.org/site/oauth2/access_token",
    pkce: false,
    clientAuthentication: "basic",
});

export type BitbucketOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createBitbucketAuth<User extends AuthUser>(
  options: BitbucketOptions<User>
): AuthPlugin<"bitbucket", OAuthOperations<User>, User> {
  return createOAuthProvider(bitbucketDefinition, {
    ...options,
  });
}
