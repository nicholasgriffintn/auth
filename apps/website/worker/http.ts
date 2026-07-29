import { AuthError, isRecord } from "@ngriffin_uk/auth-core";
import {
  parseCookies,
  serializeExpiredCookie,
  serializeSessionCookie,
} from "@ngriffin_uk/auth-cookie";

import type { DemoUser, Env, OAuthDemoProviderId } from "./types";

export const SESSION_COOKIE = "__Host-auth_session";
export const OAUTH_STATE_COOKIE = "__Host-auth_oauth_state";
export const MFA_PENDING_COOKIE = "__Host-auth_mfa_pending";

export type SecurityRoute =
  | "status"
  | "totp-start"
  | "totp-verify"
  | "webauthn-start"
  | "webauthn-verify";

export type MfaRoute = "pending" | "totp-verify" | "webauthn-verify";

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

export async function withAuthErrorResponse(
  pathname: string,
  operation: () => Response | Promise<Response>,
): Promise<Response> {
  try {
    return await operation();
  } catch (cause) {
    console.error("Authentication request failed", {
      code: cause instanceof AuthError ? cause.code : "internal_error",
      path: pathname,
    });
    return json(
      {
        error:
          cause instanceof AuthError ? cause.code : "authentication_failed",
      },
      authErrorStatus(cause),
    );
  }
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

export function pendingMfaCookie(token: string, expiresAt: Date): string {
  return serializeSessionCookie(MFA_PENDING_COOKIE, token, {
    expires: expiresAt,
    maxAge: Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1_000)),
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
      readonly provider: OAuthDemoProviderId;
      readonly action: "start" | "callback";
    }
  | null {
  const match = pathname.match(
    /^\/api\/oauth\/(amazon-cognito|github)\/(start|callback)$/u,
  );
  if (!match) return null;
  const provider = match[1];
  const action = match[2];
  if (
    (provider !== "amazon-cognito" && provider !== "github") ||
    (action !== "start" && action !== "callback")
  ) {
    return null;
  }
  return { provider, action };
}

export function parsePasswordRoute(
  pathname: string,
): "sign-in" | "sign-up" | null {
  const match = /^\/api\/password\/(sign-in|sign-up)$/u.exec(pathname);
  return match?.[1] === "sign-in" || match?.[1] === "sign-up"
    ? match[1]
    : null;
}

export function parseSecurityRoute(pathname: string): SecurityRoute | null {
  const routes: Readonly<Record<string, SecurityRoute>> = {
    "/api/security/status": "status",
    "/api/security/totp/start": "totp-start",
    "/api/security/totp/verify": "totp-verify",
    "/api/security/webauthn/start": "webauthn-start",
    "/api/security/webauthn/verify": "webauthn-verify",
  };
  return routes[pathname] ?? null;
}

export function parseMfaRoute(pathname: string): MfaRoute | null {
  if (pathname === "/api/mfa/pending") return "pending";
  if (pathname === "/api/mfa/totp/verify") return "totp-verify";
  if (pathname === "/api/mfa/webauthn/verify") {
    return "webauthn-verify";
  }
  return null;
}

export async function readJsonObject(
  request: Request,
  maxBytes = 16 * 1_024,
): Promise<Readonly<Record<string, unknown>>> {
  if (
    request.headers.get("Content-Type")?.split(";", 1)[0]?.trim() !==
    "application/json"
  ) {
    throw new AuthError("invalid_input");
  }
  const declaredLength = request.headers.get("Content-Length");
  if (
    declaredLength &&
    (!/^\d+$/u.test(declaredLength) || Number(declaredLength) > maxBytes)
  ) {
    throw new AuthError("invalid_input");
  }

  const reader = request.body?.getReader();
  if (!reader) throw new AuthError("invalid_input");
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let byteLength = 0;
  let text = "";

  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      byteLength += chunk.value.byteLength;
      if (byteLength > maxBytes) {
        await reader.cancel();
        throw new AuthError("invalid_input");
      }
      text += decoder.decode(chunk.value, { stream: true });
    }
    text += decoder.decode();
    const value: unknown = JSON.parse(text);
    if (!isRecord(value)) throw new AuthError("invalid_input");
    return value;
  } catch (cause) {
    if (cause instanceof AuthError) throw cause;
    throw new AuthError("invalid_input", undefined, { cause });
  }
}

function authErrorStatus(cause: unknown): number {
  if (!(cause instanceof AuthError)) return 500;
  if (cause.code === "provider_not_found") return 503;
  if (cause.code === "rate_limited") return 429;
  if (cause.code === "session_expired") return 401;
  if (cause.code === "provider_error") return 502;
  if (cause.code === "storage_error") return 503;
  return 400;
}

export function publicUser(user: DemoUser): Omit<DemoUser, "createdAt"> {
  const { createdAt: _createdAt, ...publicFields } = user;
  return publicFields;
}
