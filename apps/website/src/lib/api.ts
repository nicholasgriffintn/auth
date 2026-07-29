export interface DemoProvider {
  readonly id: "discord" | "github" | "google";
  readonly label: string;
  readonly configured: boolean;
}

export interface DemoUser {
  readonly id: string;
  readonly email: string;
  readonly displayName: string;
  readonly avatarUrl?: string;
  readonly provider: string;
}

export interface SessionResponse {
  readonly user: DemoUser | null;
}

export async function getDemoProviders(): Promise<readonly DemoProvider[]> {
  const response = await fetch("/api/providers", {
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error("Could not load the provider demos.");
  const body: unknown = await response.json();
  if (!isProviders(body)) throw new Error("The provider response was invalid.");
  return body.providers;
}

export async function getDemoSession(): Promise<DemoUser | null> {
  const response = await fetch("/api/session", {
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error("Could not load the demo session.");
  const body: unknown = await response.json();
  if (!isSession(body)) throw new Error("The session response was invalid.");
  return body.user;
}

export async function signOutDemo(): Promise<void> {
  const response = await fetch("/api/session/logout", {
    method: "POST",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error("Could not end the demo session.");
}

function isProviders(
  value: unknown,
): value is { readonly providers: readonly DemoProvider[] } {
  if (!isRecord(value) || !Array.isArray(value.providers)) return false;
  return value.providers.every(
    (provider) =>
      isRecord(provider) &&
      (provider.id === "discord" ||
        provider.id === "github" ||
        provider.id === "google") &&
      typeof provider.label === "string" &&
      typeof provider.configured === "boolean",
  );
}

function isSession(value: unknown): value is SessionResponse {
  if (!isRecord(value)) return false;
  if (value.user === null) return true;
  return (
    isRecord(value.user) &&
    typeof value.user.id === "string" &&
    typeof value.user.email === "string" &&
    typeof value.user.displayName === "string" &&
    typeof value.user.provider === "string" &&
    (value.user.avatarUrl === undefined ||
      typeof value.user.avatarUrl === "string")
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
