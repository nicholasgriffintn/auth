import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { AuthError } from "@ngriffin_uk/auth-core";

import { parseTokenResponse } from "./tokens.js";

describe("OAuth token responses", () => {
  it("requires bounded non-empty token values and a valid clock", () => {
    for (const value of [
      { access_token: "", token_type: "Bearer" },
      { access_token: "token", token_type: "" },
      {
        access_token: "token",
        token_type: "Bearer",
        refresh_token: "",
      },
    ]) {
      assert.throws(
        () => parseTokenResponse(value, new Date()),
        (error) =>
          error instanceof AuthError &&
          error.code === "oauth_exchange_failed"
      );
    }
    assert.throws(
      () =>
        parseTokenResponse(
          {
            access_token: "token",
            token_type: "Bearer",
            expires_in: 60,
          },
          new Date(Number.NaN)
        ),
      (error) =>
        error instanceof AuthError && error.code === "oauth_exchange_failed"
    );
  });
});
