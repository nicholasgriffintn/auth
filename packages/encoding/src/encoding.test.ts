import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  decodeBase32,
  decodeBase64,
  decodeBase64Url,
  decodeHex,
  encodeBase32,
  encodeBase64,
  encodeBase64Url,
  encodeHex,
} from "./index.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

describe("encoding primitives", () => {
  it("matches RFC 4648 vectors", () => {
    const bytes = textEncoder.encode("foobar");
    assert.equal(encodeHex(bytes), "666f6f626172");
    assert.equal(encodeBase32(bytes), "MZXW6YTBOI");
    assert.equal(encodeBase64(bytes), "Zm9vYmFy");
    assert.equal(encodeBase64Url(bytes), "Zm9vYmFy");

    assert.equal(textDecoder.decode(decodeHex("666F6F626172")), "foobar");
    assert.equal(textDecoder.decode(decodeBase32("mzxw6ytboi")), "foobar");
    assert.equal(textDecoder.decode(decodeBase64("Zm9vYmFy")), "foobar");
    assert.equal(textDecoder.decode(decodeBase64Url("Zm9vYmFy")), "foobar");
  });

  it("handles URL-safe bytes and optional padding", () => {
    const bytes = Uint8Array.from([251, 255]);
    assert.equal(encodeBase64Url(bytes), "-_8");
    assert.equal(encodeBase64Url(bytes, true), "-_8=");
    assert.deepEqual(decodeBase64Url("-_8"), bytes);
    assert.deepEqual(decodeBase64Url("-_8="), bytes);
  });

  it("rejects malformed and non-canonical input", () => {
    assert.throws(() => decodeHex("0"));
    assert.throws(() => decodeBase64("abc"));
    assert.throws(() => decodeBase64Url("a"));
    assert.throws(() => decodeBase64Url("="));
    assert.throws(() => decodeBase64Url("-_8=="));
    assert.throws(() => decodeBase32("MZ"));
    assert.throws(() => decodeBase32("="));
    assert.throws(() => decodeBase32("MY="));
    assert.equal(textDecoder.decode(decodeBase32("MY======")), "f");
  });
});
