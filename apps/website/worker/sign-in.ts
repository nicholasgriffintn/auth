import {
  AuthError,
  type AuthFlowResult,
} from "@ngriffin_uk/auth-core";
import { assertRequestCsrf } from "@ngriffin_uk/auth-request";

import { authFlowResponse } from "./auth-response.ts";
import type { AuthStore } from "./auth-store";
import {
  canonicalOrigin,
  expiredCookie,
  MFA_PENDING_COOKIE,
  readCookie,
  readJsonObject,
  type MfaRoute,
} from "./http.ts";
import { requiredString } from "./input.ts";
import { createDemoMfaAuth } from "./mfa.ts";
import {
  parsePasswordInput,
  passwordOperations,
} from "./password.ts";
import { assertAuthRateLimit } from "./rate-limit.ts";
import type { DemoUser, Env } from "./types";
import { authenticationResponse } from "./webauthn-input.ts";

export async function startPasswordSignIn(
  request: Request,
  env: Env,
  store: DurableObjectStub<AuthStore>,
): Promise<Response> {
  const origin = canonicalOrigin(request, env);
  const input = parsePasswordInput(await readJsonObject(request));
  const user = await passwordOperations(store).verifyCredentials(input);
  const auth = await createDemoMfaAuth(store, env, origin);
  return authFlowResponse(await startMfaForUser(auth, store, user));
}

export async function hasConfiguredMfa(
  store: DurableObjectStub<AuthStore>,
  userId: string,
): Promise<boolean> {
  const [totpConfigured, passkeyCount] = await Promise.all([
    store.hasOtpCredential(userId),
    store.countWebAuthnCredentials(userId),
  ]);
  return totpConfigured || passkeyCount > 0;
}

export async function issuePendingMfa(
  store: DurableObjectStub<AuthStore>,
  env: Env,
  origin: string,
  userId: string,
) {
  const auth = await createDemoMfaAuth(store, env, origin);
  return auth.issueChallenge("demo-mfa-pending", "custom", { userId });
}

async function startMfaForUser(
  auth: Awaited<ReturnType<typeof createDemoMfaAuth>>,
  store: DurableObjectStub<AuthStore>,
  user: DemoUser,
): Promise<AuthFlowResult<DemoUser>> {
  const [totpConfigured, passkeyCount] = await Promise.all([
    store.hasOtpCredential(user.id),
    store.countWebAuthnCredentials(user.id),
  ]);
  if (passkeyCount > 0) {
    const primary = await auth.providers.webauthn.startAuthentication(user.id);
    if (primary.status !== "webauthn_challenge_required") {
      throw new AuthError("unsupported_operation");
    }
    if (!totpConfigured) return primary;

    const fallback = await createOtpChallenge(auth, user.id);
    return {
      ...primary,
      challenge: {
        ...primary.challenge,
        parameters: {
          ...primary.challenge.parameters,
          alternativeChallengeKind: fallback.challenge.kind,
          alternativeContinuationToken:
            fallback.challenge.continuationToken,
          alternativeExpiresAt: fallback.challenge.expiresAt.toISOString(),
          alternativeMethod: "totp_or_recovery",
        },
      },
    };
  }

  if (totpConfigured) {
    return createOtpChallenge(auth, user.id);
  }

  const session = await auth.createSession(user.id);
  return {
    status: "authenticated",
    session: {
      user,
      token: session.token,
      expiresAt: session.expiresAt,
    },
  };
}

export async function handleMfaVerification(
  request: Request,
  env: Env,
  store: DurableObjectStub<AuthStore>,
  route: MfaRoute,
): Promise<Response> {
  if (request.method !== "POST") {
    throw new AuthError("unsupported_operation");
  }
  const origin = canonicalOrigin(request, env);
  assertRequestCsrf(request, [origin]);
  await assertAuthRateLimit(request, env, `mfa:${route}`);
  const auth = await createDemoMfaAuth(store, env, origin);

  if (route === "pending") {
    const pendingToken = readCookie(request, MFA_PENDING_COOKIE);
    if (!pendingToken) throw new AuthError("challenge_expired");
    const pending = await auth.consumeChallenge(
      pendingToken,
      "demo-mfa-pending",
      ["custom"],
    );
    const userId = requiredString(pending.payload, "userId", 1_024);
    const user = await store.findUser(userId);
    if (!user) throw new AuthError("challenge_expired");
    const response = authFlowResponse(
      await startMfaForUser(auth, store, user),
    );
    response.headers.append(
      "Set-Cookie",
      expiredCookie(MFA_PENDING_COOKIE),
    );
    return response;
  }

  const body = await readJsonObject(
    request,
    route === "webauthn-verify" ? 160 * 1_024 : undefined,
  );
  const token = requiredString(body, "token", 2_048);

  if (route === "webauthn-verify") {
    return authFlowResponse(
      await auth.providers.webauthn.finishAuthentication({
        token,
        response: authenticationResponse(body),
      }),
    );
  }

  const code = requiredString(body, "code", 32);
  const result = isTotpCode(code)
    ? await auth.providers.otp.verifyChallenge({ token, code })
    : await auth.providers.otp.useRecoveryCode({ token, code });
  return authFlowResponse(result);
}

type OtpChallengeResult = Extract<
  AuthFlowResult<DemoUser>,
  { readonly status: "mfa_challenge_required" }
>;

async function createOtpChallenge(
  auth: Awaited<ReturnType<typeof createDemoMfaAuth>>,
  userId: string,
): Promise<OtpChallengeResult> {
  const result = await auth.providers.otp.createChallenge(userId);
  if (result.status !== "mfa_challenge_required") {
    throw new AuthError("unsupported_operation");
  }
  return {
    ...result,
    challenge: {
      ...result.challenge,
      parameters: { method: "totp_or_recovery" },
    },
  };
}

function isTotpCode(value: string): boolean {
  return /^[0-9]{6}$/u.test(value);
}
