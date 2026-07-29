import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  authStateReducer,
  INITIAL_AUTH_STATE,
} from "./state.js";

describe("authentication UI state", () => {
  it("moves shared challenge results into the challenge view", () => {
    const state = authStateReducer(INITIAL_AUTH_STATE, {
      type: "result",
      result: {
        status: "mfa_challenge_required",
        challenge: {
          kind: "software_token_mfa",
          continuationToken: "opaque",
          expiresAt: "2026-01-01T00:10:00.000Z",
        },
      },
    });

    assert.equal(state.view, "challenge");
    assert.equal(state.challenge?.kind, "software_token_mfa");
    assert.equal(state.submitting, false);
  });

  it("clears challenge and error state when navigating", () => {
    const state = authStateReducer(
      {
        view: "challenge",
        challenge: {
          kind: "email_otp",
          continuationToken: "opaque",
          expiresAt: "2026-01-01T00:10:00.000Z",
        },
        submitting: false,
        error: "Old error",
      },
      { type: "navigate", view: "sign_in" }
    );

    assert.deepEqual(state, { view: "sign_in", submitting: false });
  });

  it("returns completed operations to their requested view", () => {
    const state = authStateReducer(INITIAL_AUTH_STATE, {
      type: "result",
      result: { status: "completed", next: "sign_up" },
    });

    assert.equal(state.view, "sign_up");
    assert.equal(state.status, "Authentication step completed.");
  });

  it("leaves an enrolment challenge after authentication succeeds", () => {
    const state = authStateReducer(
      {
        view: "challenge",
        challenge: {
          kind: "mfa_setup",
          continuationToken: "opaque",
          expiresAt: "2026-01-01T00:10:00.000Z",
        },
        submitting: true,
      },
      {
        type: "result",
        result: { status: "authenticated" },
      },
    );

    assert.deepEqual(state, {
      view: "sign_in",
      submitting: false,
      status: "Authentication complete.",
    });
  });

  it("switches to a server-issued fallback challenge", () => {
    const challenge = {
      kind: "software_token_mfa" as const,
      continuationToken: "otp-token",
      expiresAt: "2026-01-01T00:10:00.000Z",
    };
    assert.deepEqual(
      authStateReducer(
        { view: "challenge", submitting: true },
        { type: "challenge", challenge },
      ),
      {
        view: "challenge",
        challenge,
        submitting: false,
      },
    );
  });
});
