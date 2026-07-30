import assert from "node:assert/strict";
import { test } from "node:test";

import { resolveBrowserWebAuthn } from "./browser-webauthn.js";

test("reports unsupported passkeys before starting a browser ceremony", async () => {
  await assert.rejects(
    resolveBrowserWebAuthn({
      kind: "webauthn",
      continuationToken: "challenge-token",
      expiresAt: "2026-07-30T12:00:00.000Z",
    }),
    /Passkeys are not supported/
  );
});
