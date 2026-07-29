import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export function mastodonDefinition(baseUrl: string) {
  return defineOAuthProvider({
    name: "mastodon",
    authorizationEndpoint: joinProviderUrl(baseUrl, "/oauth/authorize"),
    tokenEndpoint: joinProviderUrl(baseUrl, "/oauth/token"),
    revocationEndpoint: joinProviderUrl(baseUrl, "/oauth/revoke"),
    pkce: true,
    clientAuthentication: "basic",
  });
}

export type MastodonOptions<User extends AuthUser> = OAuthProviderPluginOptions<User> & { readonly clientSecret: string };

export function createMastodonAuth<User extends AuthUser>(
  baseUrl: string,
  options: MastodonOptions<User>
): AuthPlugin<"mastodon", OAuthOperations<User>, User> {
  return createOAuthProvider(mastodonDefinition(baseUrl), {
    ...options,
  });
}
