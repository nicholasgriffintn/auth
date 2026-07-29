import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export const polarDefinition = defineOAuthProvider({
    name: "polar",
    authorizationEndpoint: "https://polar.sh/oauth2/authorize",
    tokenEndpoint: "https://api.polar.sh/v1/oauth2/token",
    revocationEndpoint: "https://api.polar.sh/v1/oauth2/revoke",
    pkce: true,
    clientAuthentication: "body",
});

export type PolarOptions<User extends AuthUser> = OAuthProviderPluginOptions<User>;

export function createPolarAuth<User extends AuthUser>(
  options: PolarOptions<User>
): AuthPlugin<"polar", OAuthOperations<User>, User> {
  return createOAuthProvider(polarDefinition, {
    ...options,
    clientAuthentication:
      options.clientAuthentication ?? (options.clientSecret ? "basic" : "none"),
  });
}
