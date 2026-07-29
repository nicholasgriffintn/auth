import { AuthError } from "@ngriffin_uk/auth-core";
import { assertRequestCsrf } from "@ngriffin_uk/auth-request";

import { AuthStore } from "./auth-store";
import {
  canonicalOrigin,
  expiredCookie,
  json,
  OAUTH_STATE_COOKIE,
  oauthStateCookie,
  parseOAuthRoute,
  publicUser,
  readCookie,
  redirect,
  SESSION_COOKIE,
  sessionCookie,
} from "./http";
import { providerOperations, providerSummaries } from "./oauth";
import { createBaseAuth } from "./storage-adapters";
import type { DemoProviderId, Env } from "./types";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const store = env.AUTH_STORE.getByName("website");

    try {
      if (url.pathname === "/api/providers" && request.method === "GET") {
        return json({ providers: providerSummaries(env) });
      }

      if (url.pathname === "/api/session" && request.method === "GET") {
        const token = readCookie(request, SESSION_COOKIE);
        if (!token) return json({ user: null });
        const user = await createBaseAuth(store).validateSession(token);
        return json({ user: user ? publicUser(user) : null });
      }

      if (url.pathname === "/api/session/logout" && request.method === "POST") {
        const origin = canonicalOrigin(request, env);
        assertRequestCsrf(request, [origin]);
        const token = readCookie(request, SESSION_COOKIE);
        if (token) await createBaseAuth(store).revokeSession(token);
        return json(
          { ok: true },
          200,
          { "Set-Cookie": expiredCookie(SESSION_COOKIE) },
        );
      }

      const oauthRoute = parseOAuthRoute(url.pathname);
      if (oauthRoute?.action === "start" && request.method === "GET") {
        await assertStartRateLimit(request, env, oauthRoute.provider);
        return startOAuth(request, env, store, oauthRoute.provider);
      }
      if (oauthRoute?.action === "callback" && request.method === "GET") {
        return completeOAuth(request, env, store, oauthRoute.provider);
      }

      return json({ error: "not_found" }, 404);
    } catch (cause) {
      console.error("Authentication request failed", {
        code: cause instanceof AuthError ? cause.code : "internal_error",
        path: url.pathname,
      });
      return json(
        {
          error:
            cause instanceof AuthError ? cause.code : "authentication_failed",
        },
        errorStatus(cause),
      );
    }
  },
};

async function startOAuth(
  request: Request,
  env: Env,
  store: DurableObjectStub<AuthStore>,
  provider: DemoProviderId,
): Promise<Response> {
  const origin = canonicalOrigin(request, env);
  const authorizationUrl = await providerOperations(
    provider,
    env,
    store,
    origin,
  ).startAuthorization();
  const state = authorizationUrl.searchParams.get("state");
  if (!state) throw new AuthError("provider_error");
  return redirect(authorizationUrl.href, oauthStateCookie(state));
}

async function completeOAuth(
  request: Request,
  env: Env,
  store: DurableObjectStub<AuthStore>,
  provider: DemoProviderId,
): Promise<Response> {
  const url = new URL(request.url);
  const origin = canonicalOrigin(request, env);
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  const stateCookie = readCookie(request, OAUTH_STATE_COOKIE);
  const destination = new URL("/demo", origin);

  if (!state || !code || !stateCookie || state !== stateCookie) {
    destination.searchParams.set("error", "invalid_callback");
    return redirect(destination.href, expiredCookie(OAUTH_STATE_COOKIE));
  }

  try {
    const result = await providerOperations(
      provider,
      env,
      store,
      origin,
    ).completeAuthorization({ code, state });
    if (result.status !== "authenticated") {
      throw new AuthError("unsupported_operation");
    }
    const response = redirect(
      destination.href,
      expiredCookie(OAUTH_STATE_COOKIE),
    );
    response.headers.append(
      "Set-Cookie",
      sessionCookie(result.session.token, result.session.expiresAt),
    );
    return response;
  } catch (cause) {
    console.error("OAuth callback failed", {
      code: cause instanceof AuthError ? cause.code : "internal_error",
      provider,
    });
    destination.searchParams.set(
      "error",
      cause instanceof AuthError ? cause.code : "authentication_failed",
    );
    return redirect(destination.href, expiredCookie(OAUTH_STATE_COOKIE));
  }
}

function errorStatus(cause: unknown): number {
  if (!(cause instanceof AuthError)) return 500;
  if (cause.code === "provider_not_found") return 503;
  if (cause.code === "rate_limited") return 429;
  if (cause.code === "provider_error") return 502;
  return 400;
}

async function assertStartRateLimit(
  request: Request,
  env: Env,
  provider: DemoProviderId,
): Promise<void> {
  const actor = request.headers.get("CF-Connecting-IP") ?? "local";
  const result = await env.AUTH_RATE_LIMIT.limit({
    key: `${provider}:${actor}`,
  });
  if (!result.success) throw new AuthError("rate_limited");
}

export { AuthStore };
