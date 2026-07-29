import assert from "node:assert/strict";
import { test } from "node:test";

import { AuthError } from "@ngriffin_uk/auth-core";

import { SESSION_COOKIE } from "../worker/http.ts";
import { handleSecurityRequest } from "../worker/security.ts";

test("security settings require and resolve the current session", async () => {
  const user = {
    id: "user-1",
    email: "person@example.com",
    displayName: "Person",
    provider: "password",
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
  };
  const store = {
    async findSession(tokenHash: string) {
      return {
        tokenHash,
        userId: user.id,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      };
    },
    async findUser(userId: string) {
      return userId === user.id ? user : null;
    },
    async hasOtpCredential(userId: string) {
      return userId === user.id;
    },
    async countWebAuthnCredentials(userId: string) {
      return userId === user.id ? 2 : 0;
    },
  };

  await assert.rejects(
    Reflect.apply(handleSecurityRequest, undefined, [
      new Request("https://example.com/api/security/status"),
      {},
      store,
      "status",
    ]),
    (error) =>
      error instanceof AuthError && error.code === "session_expired",
  );

  const response = await Reflect.apply(handleSecurityRequest, undefined, [
    new Request("https://example.com/api/security/status", {
      headers: { Cookie: `${SESSION_COOKIE}=opaque-session` },
    }),
    {},
    store,
    "status",
  ]);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    totpConfigured: true,
    passkeyCount: 2,
  });
});
