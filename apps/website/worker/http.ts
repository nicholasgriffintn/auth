import {
  parseCookies,
  serializeExpiredCookie,
  serializeSessionCookie,
} from "@ngriffin_uk/auth-cookie";

import type { DemoProviderId, DemoUser, Env } from "./types";

export const SESSION_COOKIE = "__Host-auth_session";
export const OAUTH_STATE_COOKIE = "__Host-auth_oauth_state";

const apiHeaders = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json; charset=utf-8",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
} as const;

export function json(
  body: unknown,
  status = 200,
  headers?: HeadersInit,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...apiHeaders, ...headers },
  });
}

export function redirect(location: string, cookie?: string): Response {
  const headers = new Headers({
    "Cache-Control": "no-store",
    Location: location,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  if (cookie) headers.append("Set-Cookie", cookie);
  return new Response(null, { status: 302, headers });
}

export function readCookie(request: Request, name: string): string | undefined {
  return parseCookies(request.headers.get("Cookie") ?? "").get(name);
}

export function sessionCookie(token: string, expiresAt: Date): string {
  return serializeSessionCookie(SESSION_COOKIE, token, {
    expires: expiresAt,
    maxAge: Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1_000)),
    priority: "high",
  });
}

export function oauthStateCookie(state: string): string {
  return serializeSessionCookie(OAUTH_STATE_COOKIE, state, {
    maxAge: 10 * 60,
    priority: "high",
  });
}

export function expiredCookie(name: string): string {
  return serializeExpiredCookie(name, {
    path: "/",
    httpOnly: true,
    sameSite: "lax",
    secure: true,
  });
}

export function canonicalOrigin(
  request: Request,
  env: Pick<Env, "SITE_ORIGIN">,
): string {
  const value = env.SITE_ORIGIN?.trim() || new URL(request.url).origin;
  const origin = new URL(value);
  if (
    (origin.protocol !== "https:" &&
      !(origin.protocol === "http:" && origin.hostname === "localhost")) ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  ) {
    throw new TypeError("SITE_ORIGIN must be a secure HTTP origin.");
  }
  return origin.origin;
}

export function parseOAuthRoute(
  pathname: string,
):
  | {
      readonly provider: DemoProviderId;
      readonly action: "start" | "callback";
    }
  | null {
  const match = pathname.match(
    /^\/api\/oauth\/(discord|github|google)\/(start|callback)$/u,
  );
  if (!match) return null;
  const provider = match[1];
  const action = match[2];
  if (
    (provider !== "discord" &&
      provider !== "github" &&
      provider !== "google") ||
    (action !== "start" && action !== "callback")
  ) {
    return null;
  }
  return { provider, action };
}

export function publicUser(user: DemoUser): Omit<DemoUser, "createdAt"> {
  const { createdAt: _createdAt, ...publicFields } = user;
  return publicFields;
}
