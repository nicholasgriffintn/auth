import assert from "node:assert/strict";
import { test } from "node:test";

import { encodeBase64Url } from "@ngriffin_uk/auth-encoding";

import { createAuthEncryption } from "../worker/encryption.ts";

test("authentication secrets are encrypted with context binding", async () => {
  const key = encodeBase64Url(new Uint8Array(32).fill(17));
  const encryption = await createAuthEncryption(key);
  const encrypted = await encryption.encryptJson(
    { userId: "user-1", secret: "not-plaintext" },
    "challenge:one",
  );

  assert.doesNotMatch(encrypted.ciphertext, /not-plaintext/u);
  assert.deepEqual(
    await encryption.decryptJson(encrypted, "challenge:one"),
    { userId: "user-1", secret: "not-plaintext" },
  );
  await assert.rejects(
    encryption.decryptJson(encrypted, "challenge:two"),
  );
});

test("authentication encryption requires a 32-byte key", async () => {
  await assert.rejects(createAuthEncryption(undefined), /not configured/u);
  await assert.rejects(
    createAuthEncryption(encodeBase64Url(new Uint8Array(16))),
    /32 bytes/u,
  );
});
