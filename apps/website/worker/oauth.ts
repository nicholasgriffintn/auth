import { AuthError } from "@ngriffin_uk/auth-core";
import type { OAuthOperations } from "@ngriffin_uk/auth-oauth2";
import { createDiscordAuth } from "@ngriffin_uk/auth-provider-discord";
import { createGitHubAuth } from "@ngriffin_uk/auth-provider-github";
import { createGoogleAuth } from "@ngriffin_uk/auth-provider-google";

import type { AuthStore } from "./auth-store";
import { resolveProviderIdentity } from "./provider-profiles";
import { createBaseAuth, createOAuthStateStore } from "./storage-adapters";
import type { DemoProviderId, DemoUser, Env } from "./types";

interface ProviderSummary {
  readonly id: DemoProviderId;
  readonly label: string;
  readonly configured: boolean;
}

export function providerSummaries(env: Env): readonly ProviderSummary[] {
  return [
    {
      id: "github",
      label: "GitHub",
      configured: Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET),
    },
    {
      id: "google",
      label: "Google",
      configured: Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET),
    },
    {
      id: "discord",
      label: "Discord",
      configured: Boolean(env.DISCORD_CLIENT_ID),
    },
  ];
}

export function providerOperations(
  provider: DemoProviderId,
  env: Env,
  store: DurableObjectStub<AuthStore>,
  origin: string,
): OAuthOperations<DemoUser> {
  const stateStore = createOAuthStateStore(store);
  const redirectUri = `${origin}/api/oauth/${provider}/callback`;
  const resolveIdentity = (tokens: Parameters<
    typeof resolveProviderIdentity
  >[1]) => resolveProviderIdentity(provider, tokens);
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
        resolveIdentity,
      }),
    ).providers.github;
  }

  if (provider === "google") {
    const clientId = requiredCredential(env.GOOGLE_CLIENT_ID);
    const clientSecret = requiredCredential(env.GOOGLE_CLIENT_SECRET);
    return auth.use(
      createGoogleAuth<DemoUser>({
        clientId,
        clientSecret,
        redirectUri,
        scopes: ["openid", "email", "profile"],
        stateStore,
        resolveIdentity,
      }),
    ).providers.google;
  }

  const clientId = requiredCredential(env.DISCORD_CLIENT_ID);
  const clientSecret = optionalCredential(env.DISCORD_CLIENT_SECRET);
  return auth.use(
    createDiscordAuth<DemoUser>({
      clientId,
      ...(clientSecret ? { clientSecret } : {}),
      redirectUri,
      scopes: ["identify", "email"],
      stateStore,
      resolveIdentity,
    }),
  ).providers.discord;
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
