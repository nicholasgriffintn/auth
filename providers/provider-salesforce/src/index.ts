import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export function salesforceDefinition(domain: string) {
  return defineOAuthProvider({
    name: "salesforce",
    authorizationEndpoint: providerDomainUrl(domain, "/services/oauth2/authorize"),
    tokenEndpoint: providerDomainUrl(domain, "/services/oauth2/token"),
    revocationEndpoint: providerDomainUrl(domain, "/services/oauth2/revoke"),
    pkce: true,
    clientAuthentication: "basic",
  });
}

export type SalesforceOptions<User extends AuthUser> = OAuthProviderPluginOptions<User>;

export function createSalesforceAuth<User extends AuthUser>(
  domain: string,
  options: SalesforceOptions<User>
): AuthPlugin<"salesforce", OAuthOperations<User>, User> {
  return createOAuthProvider(salesforceDefinition(domain), {
    ...options,
    clientAuthentication:
      options.clientAuthentication ?? (options.clientSecret ? "basic" : "none"),
  });
}
