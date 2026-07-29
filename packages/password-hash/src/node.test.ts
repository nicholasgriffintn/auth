import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createArgon2idHasher,
  createScryptHasher,
} from "./node.js";

describe("Node password hashing", () => {
  it("hashes and verifies Argon2id", async () => {
    const hasher = createArgon2idHasher();
    const hash = await hasher.hash("correct horse battery staple");
    assert.match(hash, /^\$argon2id\$/u);
    assert.equal(await hasher.verify("correct horse battery staple", hash), true);
    assert.equal(await hasher.verify("wrong password", hash), false);
    assert.deepEqual(
      await createArgon2idHasher({ timeCost: 3 }).verifyAndCheck(
        "correct horse battery staple",
        hash
      ),
      { valid: true, needsRehash: true }
    );
  });

  it("hashes and verifies scrypt records", async () => {
    const hasher = createScryptHasher({
      cost: 2 ** 14,
      maxMemoryBytes: 32 * 1024 * 1024,
    });
    const hash = await hasher.hash("correct horse battery staple");
    assert.match(hash, /^\$scrypt\$ln=14,/u);
    assert.equal(await hasher.verify("correct horse battery staple", hash), true);
    assert.equal(await hasher.verify("wrong password", hash), false);
    assert.equal(
      await hasher.verify(
        "password",
        `$scrypt$ln=14,r=999,p=1$${"a".repeat(16)}$${"b".repeat(32)}`
      ),
      false
    );
  });
});
