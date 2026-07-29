import assert from "node:assert/strict";
import { test } from "node:test";

import { demoAuthTransport } from "../src/lib/demo-auth-transport.ts";

test("the React transport maps configured OAuth providers to Worker routes", async () => {
  assert.deepEqual(
    await demoAuthTransport.execute({
      action: "start_oauth",
      provider: "amazon-cognito",
    }),
    {
      status: "redirect_required",
      provider: "amazon-cognito",
      url: "/api/oauth/amazon-cognito/start",
    },
  );
  await assert.rejects(
    demoAuthTransport.execute({
      action: "start_oauth",
      provider: "google",
    }),
    /not available/u,
  );
});

test("the React transport maps password fields to the self-rolled endpoint", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    assert.equal(String(input), "/api/password/sign-up");
    assert.equal(init?.method, "POST");
    assert.deepEqual(JSON.parse(String(init?.body)), {
      email: "demo@example.com",
      password: "unique-password",
    });
    return Response.json({
      status: "authenticated",
      user: {
        id: "user-1",
        email: "demo@example.com",
        displayName: "demo",
        provider: "password",
      },
    });
  };

  try {
    assert.deepEqual(
      await demoAuthTransport.execute({
        action: "sign_up",
        values: {
          email: "demo@example.com",
          password: "unique-password",
          confirmPassword: "unique-password",
        },
      }),
      {
        status: "authenticated",
        user: {
          id: "user-1",
          email: "demo@example.com",
          displayName: "demo",
          provider: "password",
        },
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("password sign-in preserves an MFA challenge from the backend", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    Response.json({
      status: "webauthn_challenge_required",
      challenge: {
        kind: "webauthn",
        continuationToken: "passkey-token",
        expiresAt: "2026-01-01T00:10:00.000Z",
        parameters: {
          ceremony: "authentication",
          alternativeChallengeKind: "software_token_mfa",
          alternativeContinuationToken: "otp-token",
          alternativeExpiresAt: "2026-01-01T00:10:00.000Z",
          alternativeMethod: "totp_or_recovery",
        },
      },
    });

  try {
    const result = await demoAuthTransport.execute({
      action: "sign_in",
      values: {
        email: "demo@example.com",
        password: "unique-password",
      },
    });
    assert.equal(result.status, "webauthn_challenge_required");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("OAuth sign-in resumes its pending local MFA challenge", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    assert.equal(String(input), "/api/mfa/pending");
    assert.equal(init?.method, "POST");
    return Response.json({
      status: "mfa_challenge_required",
      challenge: {
        kind: "software_token_mfa",
        continuationToken: "otp-token",
        expiresAt: "2026-01-01T00:10:00.000Z",
        parameters: { method: "totp_or_recovery" },
      },
    });
  };

  try {
    const result = await demoAuthTransport.execute({ action: "resume_mfa" });
    assert.equal(result.status, "mfa_challenge_required");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the React transport runs TOTP setup through package challenges", async () => {
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  globalThis.fetch = async (input, init) => {
    calls.push(String(input));
    assert.equal(init?.method, "POST");
    if (String(input).endsWith("/start")) {
      return Response.json({
        status: "mfa_setup_required",
        challenge: {
          kind: "mfa_setup",
          continuationToken: "opaque-totp",
          expiresAt: "2026-01-01T00:10:00.000Z",
          parameters: {
            secret: "ABC123",
            recoveryCodes: ["recovery-one"],
          },
        },
      });
    }
    assert.deepEqual(JSON.parse(String(init?.body)), {
      token: "opaque-totp",
      code: "123456",
    });
    return Response.json({
      status: "authenticated",
      user: {
        id: "user-1",
        email: "demo@example.com",
        displayName: "demo",
        provider: "password",
      },
    });
  };

  try {
    const started = await demoAuthTransport.execute({
      action: "start_totp_setup",
    });
    assert.equal(started.status, "mfa_setup_required");
    const completed = await demoAuthTransport.execute({
      action: "continue",
      continuationToken: "opaque-totp",
      kind: "mfa_setup",
      values: { code: "123456" },
    });
    assert.equal(completed.status, "authenticated");
    assert.deepEqual(calls, [
      "/api/security/totp/start",
      "/api/security/totp/verify",
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the React transport serialises browser passkey registration", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    assert.equal(String(input), "/api/security/webauthn/verify");
    assert.deepEqual(JSON.parse(String(init?.body)), {
      token: "opaque-passkey",
      credentialId: "credential",
      clientDataJSON: "client-data",
      attestationObject: "attestation",
      transports: ["internal"],
    });
    return Response.json({
      status: "authenticated",
      user: {
        id: "user-1",
        email: "demo@example.com",
        displayName: "demo",
        provider: "password",
      },
    });
  };

  try {
    const completed = await demoAuthTransport.execute({
      action: "continue",
      continuationToken: "opaque-passkey",
      kind: "webauthn",
      values: {
        ceremony: "registration",
        credentialId: "credential",
        clientDataJSON: "client-data",
        attestationObject: "attestation",
        transports: "[\"internal\"]",
      },
    });
    assert.equal(completed.status, "authenticated");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the React transport verifies passkey and TOTP sign-in challenges", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ readonly path: string; readonly body: unknown }> = [];
  globalThis.fetch = async (input, init) => {
    calls.push({
      path: String(input),
      body: JSON.parse(String(init?.body)),
    });
    return Response.json({
      status: "authenticated",
      user: {
        id: "user-1",
        email: "demo@example.com",
        displayName: "demo",
        provider: "password",
      },
    });
  };

  try {
    await demoAuthTransport.execute({
      action: "continue",
      continuationToken: "passkey-token",
      kind: "webauthn",
      values: {
        ceremony: "authentication",
        credentialId: "credential",
        clientDataJSON: "client-data",
        authenticatorData: "authenticator-data",
        signature: "signature",
      },
    });
    await demoAuthTransport.execute({
      action: "continue",
      continuationToken: "otp-token",
      kind: "software_token_mfa",
      values: { code: "abcd-efgh-ijkl-mnop" },
    });
    assert.deepEqual(calls, [
      {
        path: "/api/mfa/webauthn/verify",
        body: {
          token: "passkey-token",
          credentialId: "credential",
          clientDataJSON: "client-data",
          authenticatorData: "authenticator-data",
          signature: "signature",
        },
      },
      {
        path: "/api/mfa/totp/verify",
        body: {
          token: "otp-token",
          code: "abcd-efgh-ijkl-mnop",
        },
      },
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the React transport does not expose non-JSON response parsing errors", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response("<!DOCTYPE html><title>Internal error</title>", {
      status: 500,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });

  try {
    await assert.rejects(
      demoAuthTransport.execute({
        action: "sign_in",
        values: {
          email: "demo@example.com",
          password: "unique-password",
        },
      }),
      /^Error: Authentication could not be completed\.$/u,
    );
    await assert.rejects(
      demoAuthTransport.execute({
        action: "continue",
        continuationToken: "expired-token",
        kind: "software_token_mfa",
        values: { code: "123456" },
      }),
      /^Error: Security verification could not be completed\.$/u,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the React transport presents safe authentication error messages", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) =>
    Response.json(
      {
        error: String(input).startsWith("/api/password/")
          ? "invalid_credentials"
          : "challenge_expired",
      },
      { status: 400 },
    );

  try {
    await assert.rejects(
      demoAuthTransport.execute({
        action: "sign_in",
        values: {
          email: "demo@example.com",
          password: "wrong-password",
        },
      }),
      /^Error: The email address or password is incorrect\.$/u,
    );
    await assert.rejects(
      demoAuthTransport.execute({
        action: "continue",
        continuationToken: "expired-token",
        kind: "software_token_mfa",
        values: { code: "123456" },
      }),
      /^Error: This sign-in attempt expired\. Sign in again\.$/u,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
