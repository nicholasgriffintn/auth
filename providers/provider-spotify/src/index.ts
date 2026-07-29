import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const spotifyDefinition = defineOAuthProvider({
    name: "spotify",
    authorizationEndpoint: "https://accounts.spotify.com/authorize",
    tokenEndpoint: "https://accounts.spotify.com/api/token",
    pkce: true,
    clientAuthentication: "basic",
});

export type SpotifyOptions<User extends AuthUser> = OAuthProviderPluginOptions<User>;

export function createSpotifyAuth<User extends AuthUser>(
  options: SpotifyOptions<User>
): AuthPlugin<"spotify", OAuthOperations<User>, User> {
  return createOAuthProvider(spotifyDefinition, {
    ...options,
    clientAuthentication:
      options.clientAuthentication ?? (options.clientSecret ? "basic" : "none"),
  });
}
