import {
  AuthError,
  type AuthFlowResult,
} from "@ngriffin_uk/auth-core";
import { assertRequestCsrf } from "@ngriffin_uk/auth-request";

import type { AuthStore } from "./auth-store";
import {
  canonicalOrigin,
  json,
  publicUser,
  readCookie,
  readJsonObject,
  SESSION_COOKIE,
  sessionCookie,
  type SecurityRoute,
} from "./http.ts";
import { requiredString } from "./input.ts";
import { createDemoMfaAuth } from "./mfa.ts";
import { assertAuthRateLimit } from "./rate-limit.ts";
import {
  createBaseAuth,
} from "./storage-adapters.ts";
import type { DemoUser, Env } from "./types";
import { registrationResponse } from "./webauthn-input.ts";

const MAX_PASSKEYS_PER_USER = 10;

export async function handleSecurityRequest(
  request: Request,
  env: Env,
  store: DurableObjectStub<AuthStore>,
  route: SecurityRoute,
): Promise<Response> {
  const baseAuth = createBaseAuth(store);
  const currentToken = readCookie(request, SESSION_COOKIE);
  const currentSession = currentToken
    ? await baseAuth.authenticate(currentToken)
    : null;
  if (!currentToken || !currentSession) {
    throw new AuthError("session_expired");
  }

  if (route === "status") {
    if (request.method !== "GET") return json({ error: "not_found" }, 404);
    const [totpConfigured, passkeyCount] = await Promise.all([
      store.hasOtpCredential(currentSession.user.id),
      store.countWebAuthnCredentials(currentSession.user.id),
    ]);
    return json({ totpConfigured, passkeyCount });
  }

  if (request.method !== "POST") return json({ error: "not_found" }, 404);
  const origin = canonicalOrigin(request, env);
  assertRequestCsrf(request, [origin]);
  await assertAuthRateLimit(request, env, `security:${route}`);

  const auth = await createDemoMfaAuth(store, env, origin);

  if (route === "totp-start") {
    return challengeResponse(
      await auth.providers.otp.startSetup({
        userId: currentSession.user.id,
        accountName: currentSession.user.email,
      }),
    );
  }

  if (route === "totp-verify") {
    const body = await readJsonObject(request);
    return completeEnrolment(
      await auth.providers.otp.verifySetup({
        token: requiredString(body, "token", 2_048),
        code: requiredString(body, "code", 32),
        expectedUserId: currentSession.user.id,
      }),
      currentToken,
      baseAuth,
    );
  }

  if (route === "webauthn-start") {
    if (
      (await store.countWebAuthnCredentials(currentSession.user.id)) >=
      MAX_PASSKEYS_PER_USER
    ) {
      throw new AuthError("invalid_input", "The passkey limit was reached.");
    }
    return challengeResponse(
      await auth.providers.webauthn.startRegistration({
        userId: currentSession.user.id,
        userName: currentSession.user.email,
        displayName: currentSession.user.displayName,
      }),
    );
  }

  const body = await readJsonObject(request, 160 * 1_024);
  return completeEnrolment(
    await auth.providers.webauthn.finishRegistration({
      token: requiredString(body, "token", 2_048),
      response: registrationResponse(body),
      expectedUserId: currentSession.user.id,
    }),
    currentToken,
    baseAuth,
  );
}

function challengeResponse(result: AuthFlowResult<DemoUser>): Response {
  if (!("challenge" in result)) {
    throw new AuthError("unsupported_operation");
  }
  return json({
    status: result.status,
    challenge: {
      ...result.challenge,
      expiresAt: result.challenge.expiresAt.toISOString(),
    },
  });
}

async function completeEnrolment(
  result: AuthFlowResult<DemoUser>,
  currentToken: string,
  baseAuth: ReturnType<typeof createBaseAuth>,
): Promise<Response> {
  if (result.status !== "authenticated") {
    throw new AuthError("unsupported_operation");
  }
  await baseAuth.revokeSession(currentToken);
  return json(
    {
      status: "authenticated",
      user: publicUser(result.session.user),
    },
    200,
    {
      "Set-Cookie": sessionCookie(
        result.session.token,
        result.session.expiresAt,
      ),
    },
  );
}
