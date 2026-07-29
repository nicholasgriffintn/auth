import { AuthError } from "@ngriffin_uk/auth-core";
import { assertRequestCsrf } from "@ngriffin_uk/auth-request";

import { AuthStore } from "./auth-store";
import { authFlowResponse } from "./auth-response";
import {
  canonicalOrigin,
  expiredCookie,
  json,
  MFA_PENDING_COOKIE,
  OAUTH_STATE_COOKIE,
  oauthStateCookie,
  pendingMfaCookie,
  parseOAuthRoute,
  parseMfaRoute,
  parsePasswordRoute,
  parseSecurityRoute,
  publicUser,
  readCookie,
  readJsonObject,
  redirect,
  SESSION_COOKIE,
  sessionCookie,
  withAuthErrorResponse,
} from "./http";
import { providerOperations } from "./oauth";
import { parsePasswordInput, passwordOperations } from "./password";
import { providerSummaries } from "./providers";
import { assertAuthRateLimit } from "./rate-limit";
import {
  handleMfaVerification,
  hasConfiguredMfa,
  issuePendingMfa,
  startPasswordSignIn,
} from "./sign-in";
import { handleSecurityRequest } from "./security";
import { createBaseAuth } from "./storage-adapters";
import type { Env, OAuthDemoProviderId } from "./types";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    return withAuthErrorResponse(url.pathname, async () => {
      const store = env.AUTH_STORE.getByName("website");

      if (url.pathname === "/api/providers" && request.method === "GET") {
        return json({ providers: providerSummaries(env) });
      }

      if (url.pathname === "/api/session" && request.method === "GET") {
        const token = readCookie(request, SESSION_COOKIE);
        const pendingMfa = Boolean(readCookie(request, MFA_PENDING_COOKIE));
        if (!token) return json({ user: null, pendingMfa });
        const user = await createBaseAuth(store).validateSession(token);
        return json({
          user: user ? publicUser(user) : null,
          pendingMfa,
        });
      }

      if (url.pathname === "/api/session/logout" && request.method === "POST") {
        const origin = canonicalOrigin(request, env);
        assertRequestCsrf(request, [origin]);
        const token = readCookie(request, SESSION_COOKIE);
        if (token) await createBaseAuth(store).revokeSession(token);
        const response = json(
          { ok: true },
          200,
          { "Set-Cookie": expiredCookie(SESSION_COOKIE) },
        );
        response.headers.append(
          "Set-Cookie",
          expiredCookie(MFA_PENDING_COOKIE),
        );
        return response;
      }

      const securityRoute = parseSecurityRoute(url.pathname);
      if (securityRoute) {
        return handleSecurityRequest(request, env, store, securityRoute);
      }

      const mfaRoute = parseMfaRoute(url.pathname);
      if (mfaRoute) {
        return handleMfaVerification(request, env, store, mfaRoute);
      }

      const passwordRoute = parsePasswordRoute(url.pathname);
      if (passwordRoute && request.method === "POST") {
        const origin = canonicalOrigin(request, env);
        assertRequestCsrf(request, [origin]);
        await assertAuthRateLimit(request, env, "password");
        if (passwordRoute === "sign-in") {
          return startPasswordSignIn(request, env, store);
        }
        const input = parsePasswordInput(await readJsonObject(request));
        const operations = passwordOperations(store);
        return authFlowResponse(await operations.signUp(input));
      }

      const oauthRoute = parseOAuthRoute(url.pathname);
      if (oauthRoute?.action === "start" && request.method === "GET") {
        await assertAuthRateLimit(request, env, oauthRoute.provider);
        return startOAuth(request, env, store, oauthRoute.provider);
      }
      if (oauthRoute?.action === "callback" && request.method === "GET") {
        return completeOAuth(request, env, store, oauthRoute.provider);
      }

      return json({ error: "not_found" }, 404);
    });
  },
};

async function startOAuth(
  request: Request,
  env: Env,
  store: DurableObjectStub<AuthStore>,
  provider: OAuthDemoProviderId,
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
  provider: OAuthDemoProviderId,
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
    if (await hasConfiguredMfa(store, result.session.user.id)) {
      await createBaseAuth(store).revokeSession(result.session.token);
      const pending = await issuePendingMfa(
        store,
        env,
        origin,
        result.session.user.id,
      );
      const response = redirect(
        destination.href,
        expiredCookie(OAUTH_STATE_COOKIE),
      );
      response.headers.append(
        "Set-Cookie",
        pendingMfaCookie(pending.token, pending.expiresAt),
      );
      return response;
    }
    const response = redirect(
      destination.href,
      expiredCookie(OAUTH_STATE_COOKIE),
    );
    response.headers.append(
      "Set-Cookie",
      sessionCookie(result.session.token, result.session.expiresAt),
    );
    response.headers.append(
      "Set-Cookie",
      expiredCookie(MFA_PENDING_COOKIE),
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

export { AuthStore };
