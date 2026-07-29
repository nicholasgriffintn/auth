import { AuthError } from "@ngriffin_uk/auth-core";
import {
  providerDomainUrl,
  type OAuthOperations,
} from "@ngriffin_uk/auth-oauth2";
import { createAmazonCognitoAuth } from "@ngriffin_uk/auth-provider-amazon-cognito";
import { createGitHubAuth } from "@ngriffin_uk/auth-provider-github";

import type { AuthStore } from "./auth-store";
import { resolveProviderIdentity } from "./provider-profiles";
import { createBaseAuth, createOAuthStateStore } from "./storage-adapters";
import type { DemoUser, Env, OAuthDemoProviderId } from "./types";

export function providerOperations(
  provider: OAuthDemoProviderId,
  env: Env,
  store: DurableObjectStub<AuthStore>,
  origin: string,
): OAuthOperations<DemoUser> {
  const stateStore = createOAuthStateStore(store);
  const redirectUri = `${origin}/api/oauth/${provider}/callback`;
  const auth = createBaseAuth(store);

  if (provider === "github") {
    const clientId = requiredCredential(env.GITHUB_CLIENT_ID);
    const clientSecret = requiredCredential(env.GITHUB_CLIENT_SECRET);
    return auth.use(
      createGitHubAuth<DemoUser>({
        clientId,
        clientSecret,
        redirectUri,
        scopes: ["read:user", "user:email"],
        stateStore,
        resolveIdentity: (tokens) =>
          resolveProviderIdentity("github", tokens),
      }),
    ).providers.github;
  }

  const domain = requiredCredential(env.COGNITO_DOMAIN);
  const clientId = requiredCredential(env.COGNITO_CLIENT_ID);
  const clientSecret = requiredCredential(env.COGNITO_CLIENT_SECRET);
  const userInfoEndpoint = providerDomainUrl(domain, "/oauth2/userInfo");
  return auth.use(
    createAmazonCognitoAuth<DemoUser>(domain, {
      clientId,
      clientSecret,
      redirectUri,
      scopes: ["openid", "email", "profile"],
      stateStore,
      resolveIdentity: (tokens) =>
        resolveProviderIdentity("amazon-cognito", tokens, {
          cognitoUserInfoEndpoint: userInfoEndpoint,
        }),
    }),
  ).providers["amazon-cognito"];
}

function requiredCredential(value: string | undefined): string {
  const credential = optionalCredential(value);
  if (!credential) throw new AuthError("provider_not_found");
  return credential;
}

function optionalCredential(value: string | undefined): string | undefined {
  const credential = value?.trim();
  return credential || undefined;
}
