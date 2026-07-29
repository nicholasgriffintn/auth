import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createPbkdf2Hasher } from "./pbkdf2.js";

describe("PBKDF2 password hashing", () => {
  it("salts hashes, verifies passwords, and reports upgrades", async () => {
    const fastForTest = createPbkdf2Hasher({ iterations: 1_000 });
    const hash = await fastForTest.hash("correct horse battery staple");

    assert.match(hash, /^\$pbkdf2-sha256\$i=1000\$/u);
    assert.equal(
      await fastForTest.verify("correct horse battery staple", hash),
      true
    );
    assert.equal(await fastForTest.verify("wrong password", hash), false);

    const upgraded = createPbkdf2Hasher({ iterations: 2_000 });
    assert.deepEqual(
      await upgraded.verifyAndCheck("correct horse battery staple", hash),
      { valid: true, needsRehash: true }
    );
  });

  it("rejects malformed hashes without throwing", async () => {
    const hasher = createPbkdf2Hasher({ iterations: 1_000 });
    assert.equal(await hasher.verify("password", "not-a-hash"), false);
    assert.equal(
      await hasher.verify(
        "password",
        `$pbkdf2-sha256$i=2000001$${"a".repeat(16)}$${"b".repeat(32)}`
      ),
      false
    );
  });
});
