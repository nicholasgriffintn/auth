import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  joinProviderUrl,
  providerDomainUrl,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";

export function microsoftEntraIdDefinition(tenant: string) {
  return defineOAuthProvider({
    name: "microsoft-entra-id",
    authorizationEndpoint: `https://login.microsoftonline.com/${validateSegment(tenant)}/oauth2/v2.0/authorize`,
    tokenEndpoint: `https://login.microsoftonline.com/${validateSegment(tenant)}/oauth2/v2.0/token`,
    pkce: true,
    clientAuthentication: "basic",
  });
}

export type MicrosoftEntraIdOptions<User extends AuthUser> = OAuthProviderPluginOptions<User>;

export function createMicrosoftEntraIdAuth<User extends AuthUser>(
  tenant: string,
  options: MicrosoftEntraIdOptions<User>
): AuthPlugin<"microsoft-entra-id", OAuthOperations<User>, User> {
  return createOAuthProvider(microsoftEntraIdDefinition(tenant), {
    ...options,
    clientAuthentication:
      options.clientAuthentication ?? (options.clientSecret ? "basic" : "none"),
  });
}

function validateSegment(value: string): string {
  if (!/^[A-Za-z0-9.-]+$/u.test(value)) throw new TypeError("Tenant is invalid.");
  return value;
}
