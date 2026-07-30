import assert from "node:assert/strict";
import { test } from "node:test";

import { AuthError } from "@ngriffin_uk/auth-core";
import { encodeBase64Url } from "@ngriffin_uk/auth-encoding";

import { createAuthEncryption } from "../worker/encryption.ts";
import {
  MFA_PENDING_COOKIE,
  withAuthErrorResponse,
} from "../worker/http.ts";
import {
  handleMfaVerification,
  issuePendingMfa,
  startPasswordSignIn,
} from "../worker/sign-in.ts";
import { demoPasswordHasher } from "../worker/password.ts";
import type { StoredChallengeRecord } from "../worker/auth-store.ts";

const user = {
  id: "user-1",
  email: "person@example.com",
  displayName: "Person",
  provider: "password",
  createdAt: new Date("2026-01-01T00:00:00.000Z"),
};
const passwordHashPromise = demoPasswordHasher.hash("correct-password");

test("the demo password hasher uses the Worker-compatible scrypt profile", async () => {
  const passwordHash = await passwordHashPromise;

  assert.match(passwordHash, /^\$scrypt\$ln=15,r=8,p=3\$/u);
  assert.equal(
    await demoPasswordHasher.verify("correct-password", passwordHash),
    true,
  );
});

test("password sign-in prefers passkeys and issues no session before MFA", async () => {
  const fixture = await signInFixture({ passkeys: 1, totp: true });
  const response = await Reflect.apply(startPasswordSignIn, undefined, [
    passwordRequest(),
    fixture.env,
    fixture.store,
  ]);
  const body = await response.json();

  assert.equal(body.status, "webauthn_challenge_required");
  assert.equal(body.challenge.kind, "webauthn");
  assert.equal(
    body.challenge.parameters.alternativeChallengeKind,
    "software_token_mfa",
  );
  assert.equal(fixture.sessionCount(), 0);
  assert.equal(response.headers.has("Set-Cookie"), false);
});

test("password sign-in requires TOTP when it is the configured factor", async () => {
  const fixture = await signInFixture({ passkeys: 0, totp: true });
  const response = await Reflect.apply(startPasswordSignIn, undefined, [
    passwordRequest(),
    fixture.env,
    fixture.store,
  ]);
  const body = await response.json();

  assert.equal(body.status, "mfa_challenge_required");
  assert.equal(body.challenge.kind, "software_token_mfa");
  assert.equal(body.challenge.parameters.method, "totp_or_recovery");
  assert.equal(fixture.sessionCount(), 0);
});

test("password sign-in issues a session when no second factor exists", async () => {
  const fixture = await signInFixture({ passkeys: 0, totp: false });
  const response = await Reflect.apply(startPasswordSignIn, undefined, [
    passwordRequest(),
    fixture.env,
    fixture.store,
  ]);
  const body = await response.json();

  assert.equal(body.status, "authenticated");
  assert.equal(body.user.id, user.id);
  assert.equal(fixture.sessionCount(), 1);
  assert.match(response.headers.get("Set-Cookie") ?? "", /auth_session=/u);
});

test("OAuth sign-in resumes MFA without accepting its temporary session", async () => {
  const fixture = await signInFixture({ passkeys: 0, totp: true });
  const pending = await Reflect.apply(issuePendingMfa, undefined, [
    fixture.store,
    fixture.env,
    "https://example.com",
    user.id,
  ]);
  const response = await Reflect.apply(handleMfaVerification, undefined, [
    new Request("https://example.com/api/mfa/pending", {
      method: "POST",
      headers: {
        Cookie: `${MFA_PENDING_COOKIE}=${pending.token}`,
        Origin: "https://example.com",
      },
    }),
    fixture.env,
    fixture.store,
    "pending",
  ]);
  const body = await response.json();

  assert.equal(body.status, "mfa_challenge_required");
  assert.equal(body.challenge.kind, "software_token_mfa");
  assert.match(
    response.headers.get("Set-Cookie") ?? "",
    /auth_mfa_pending=;/u,
  );
  assert.equal(fixture.sessionCount(), 0);
});

test("a recovery code completes MFA once and cannot be reused", async () => {
  const fixture = await signInFixture({ passkeys: 0, totp: true });
  const firstChallenge = await Reflect.apply(startPasswordSignIn, undefined, [
    passwordRequest(),
    fixture.env,
    fixture.store,
  ]);
  const firstBody = await firstChallenge.json();
  const verified = await Reflect.apply(handleMfaVerification, undefined, [
    mfaRequest(firstBody.challenge.continuationToken, fixture.recoveryCode),
    fixture.env,
    fixture.store,
    "totp-verify",
  ]);
  assert.equal((await verified.json()).status, "authenticated");
  assert.equal(fixture.sessionCount(), 1);

  const secondChallenge = await Reflect.apply(startPasswordSignIn, undefined, [
    passwordRequest(),
    fixture.env,
    fixture.store,
  ]);
  const secondBody = await secondChallenge.json();
  await assert.rejects(
    Reflect.apply(handleMfaVerification, undefined, [
      mfaRequest(secondBody.challenge.continuationToken, fixture.recoveryCode),
      fixture.env,
      fixture.store,
      "totp-verify",
    ]),
  );
  assert.equal(fixture.sessionCount(), 1);
});

test("the HTTP boundary returns JSON for expected authentication failures", async () => {
  const fixture = await signInFixture({ passkeys: 0, totp: true });
  const invalidPassword = await withAuthErrorResponse(
    "/api/password/sign-in",
    () =>
      Reflect.apply(startPasswordSignIn, undefined, [
        passwordRequest("wrong-password"),
        fixture.env,
        fixture.store,
      ]),
  );

  assert.equal(invalidPassword.status, 400);
  assert.match(
    invalidPassword.headers.get("Content-Type") ?? "",
    /^application\/json/u,
  );
  assert.deepEqual(await invalidPassword.json(), {
    error: "invalid_credentials",
  });

  const expiredChallenge = await withAuthErrorResponse(
    "/api/mfa/totp/verify",
    () =>
      Reflect.apply(handleMfaVerification, undefined, [
        mfaRequest("expired-token", "invalid-recovery-code"),
        fixture.env,
        fixture.store,
        "totp-verify",
      ]),
  );

  assert.equal(expiredChallenge.status, 400);
  assert.match(
    expiredChallenge.headers.get("Content-Type") ?? "",
    /^application\/json/u,
  );
  assert.deepEqual(await expiredChallenge.json(), {
    error: "challenge_expired",
  });

  const storageFailure = await withAuthErrorResponse(
    "/api/password/sign-up",
    () => {
      throw new AuthError("storage_error");
    },
  );
  assert.equal(storageFailure.status, 503);
  assert.deepEqual(await storageFailure.json(), {
    error: "storage_error",
  });
});

async function signInFixture(input: {
  readonly passkeys: number;
  readonly totp: boolean;
}) {
  const passwordHash = await passwordHashPromise;
  const encodedEncryptionKey = encodeBase64Url(new Uint8Array(32).fill(9));
  const encryption = await createAuthEncryption(encodedEncryptionKey);
  const otpSecret = await encryption.encryptBytes(
    new Uint8Array(20).fill(7),
    `otp:${user.id}`,
  );
  const recoveryCode = "abcd-efgh-ijkl-mnop";
  const normalisedRecoveryCode = recoveryCode.replaceAll("-", "");
  const recoveryCodeHash = encodeBase64Url(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(normalisedRecoveryCode),
      ),
    ),
  );
  let recoveryCodeAvailable = true;
  let sessions = 0;
  const challenges = new Map<string, StoredChallengeRecord>();
  const store = {
    async findPasswordAccountByEmail(email: string) {
      return email === user.email
        ? { user, passwordHash, emailVerified: true }
        : null;
    },
    async findPasswordAccountByUserId() {
      return null;
    },
    async findUser(userId: string) {
      return userId === user.id ? user : null;
    },
    async findUserByIdentity() {
      return null;
    },
    async createSession() {
      sessions += 1;
    },
    async findSession() {
      return null;
    },
    async deleteSession() {},
    async createChallenge(challenge: StoredChallengeRecord) {
      challenges.set(challenge.tokenHash, challenge);
    },
    async findChallenge(tokenHash: string) {
      return challenges.get(tokenHash) ?? null;
    },
    async consumeChallenge(tokenHash: string) {
      const challenge = challenges.get(tokenHash) ?? null;
      challenges.delete(tokenHash);
      return challenge;
    },
    async incrementChallengeAttempts(
      tokenHash: string,
      expectedAttempts: number,
    ) {
      const challenge = challenges.get(tokenHash);
      if (!challenge || challenge.attempts !== expectedAttempts) return false;
      challenges.set(tokenHash, {
        ...challenge,
        attempts: challenge.attempts + 1,
      });
      return true;
    },
    async hasOtpCredential() {
      return input.totp;
    },
    async findOtpCredential() {
      return input.totp
        ? {
          userId: user.id,
          secret: otpSecret,
          lastAcceptedStep: "0",
          recoveryCodeHashes: [recoveryCodeHash],
        }
        : null;
    },
    async countWebAuthnCredentials() {
      return input.passkeys;
    },
    async listWebAuthnCredentials() {
      return input.passkeys > 0
        ? [
          {
            id: encodeBase64Url(new Uint8Array([1, 2, 3])),
            userId: user.id,
            publicKeyJwk: { kty: "EC" },
            algorithm: "ES256",
            signCount: 0,
            backupEligible: true,
            backedUp: true,
            createdAt: new Date(),
            updatedAt: new Date(),
          },
        ]
        : [];
    },
    async consumeRecoveryCode(_userId: string, codeHash: string) {
      if (!recoveryCodeAvailable || codeHash !== recoveryCodeHash) return false;
      recoveryCodeAvailable = false;
      return true;
    },
    async advanceOtpStep() {
      return true;
    },
  };
  return {
    env: {
      AUTH_ENCRYPTION_KEY: encodedEncryptionKey,
      AUTH_RATE_LIMIT: {
        async limit() {
          return { success: true };
        },
      },
      SITE_ORIGIN: "https://example.com",
    },
    store,
    recoveryCode,
    sessionCount: () => sessions,
  };
}

function mfaRequest(token: string, code: string): Request {
  return new Request("https://example.com/api/mfa/totp/verify", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: "https://example.com",
    },
    body: JSON.stringify({ token, code }),
  });
}

function passwordRequest(password = "correct-password"): Request {
  return new Request("https://example.com/api/password/sign-in", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: "https://example.com",
    },
    body: JSON.stringify({
      email: user.email,
      password,
    }),
  });
}
