import type { AuthUser } from "@ngriffin_uk/auth-core";

import type { AuthStore } from "./auth-store";

export type DemoProviderId = "amazon-cognito" | "github" | "password";
export type OAuthDemoProviderId = Exclude<DemoProviderId, "password">;

export interface DemoUser extends AuthUser {
  readonly displayName: string;
  readonly avatarUrl?: string;
  readonly provider: string;
}

export interface Env {
  readonly AUTH_STORE: DurableObjectNamespace<AuthStore>;
  readonly AUTH_RATE_LIMIT: RateLimit;
  readonly AUTH_ENCRYPTION_KEY?: string;
  readonly SITE_ORIGIN?: string;
  readonly GITHUB_CLIENT_ID?: string;
  readonly GITHUB_CLIENT_SECRET?: string;
  readonly COGNITO_DOMAIN?: string;
  readonly COGNITO_CLIENT_ID?: string;
  readonly COGNITO_CLIENT_SECRET?: string;
}
