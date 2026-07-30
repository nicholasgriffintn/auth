import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export * from "./direct.js";
export * from "./direct-types.js";

export function amazonCognitoDefinition(domain: string) {
  return defineOAuthProvider({
    name: "amazon-cognito",
    authorizationEndpoint: providerDomainUrl(domain, "/oauth2/authorize"),
    tokenEndpoint: providerDomainUrl(domain, "/oauth2/token"),
    revocationEndpoint: providerDomainUrl(domain, "/oauth2/revoke"),
    pkce: true,
    clientAuthentication: "basic",
  });
}

export type AmazonCognitoOptions<User extends AuthUser> = OAuthProviderPluginOptions<User>;

export function createAmazonCognitoAuth<User extends AuthUser>(
  domain: string,
  options: AmazonCognitoOptions<User>
): AuthPlugin<"amazon-cognito", OAuthOperations<User>, User> {
  return createOAuthProvider(amazonCognitoDefinition(domain), {
    ...options,
    clientAuthentication:
      options.clientAuthentication ?? (options.clientSecret ? "basic" : "none"),
  });
}
