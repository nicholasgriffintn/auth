import assert from "node:assert/strict";
import { test } from "node:test";

import { readAppleSignInDetail } from "./apple-direct-provider.js";

test("reads direct Apple credentials without trusting unrelated event data", () => {
  const event = Object.assign(new Event("AppleIDSignInOnSuccess"), {
    detail: {
      authorization: {
        id_token: "identity-token",
        state: "request-state",
        ignored: true,
      },
      user: {
        name: {
          firstName: "Nicholas",
          lastName: "Griffin",
        },
      },
    },
  });

  assert.deepEqual(readAppleSignInDetail(event), {
    authorization: {
      id_token: "identity-token",
      state: "request-state",
    },
    user: {
      name: {
        firstName: "Nicholas",
        lastName: "Griffin",
      },
    },
  });
});
