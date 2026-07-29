import type { AuthUser } from "@ngriffin_uk/auth-core";

import type { AuthStore } from "./auth-store";

export type DemoProviderId = "discord" | "github" | "google";

export interface DemoUser extends AuthUser {
  readonly displayName: string;
  readonly avatarUrl?: string;
  readonly provider: string;
}

export interface Env {
  readonly AUTH_STORE: DurableObjectNamespace<AuthStore>;
  readonly AUTH_RATE_LIMIT: RateLimit;
  readonly SITE_ORIGIN?: string;
  readonly GITHUB_CLIENT_ID?: string;
  readonly GITHUB_CLIENT_SECRET?: string;
  readonly GOOGLE_CLIENT_ID?: string;
  readonly GOOGLE_CLIENT_SECRET?: string;
  readonly DISCORD_CLIENT_ID?: string;
  readonly DISCORD_CLIENT_SECRET?: string;
}
