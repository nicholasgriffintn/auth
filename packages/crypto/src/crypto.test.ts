import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { encodeHex } from "@ngriffin_uk/auth-encoding";

import {
  constantTimeEqual,
  hmac,
  sha256,
  signEcdsa,
  verifyEcdsa,
} from "./index.js";

const textEncoder = new TextEncoder();

describe("cryptography primitives", () => {
  it("matches SHA-256 and HMAC-SHA-256 vectors", async () => {
    assert.equal(
      encodeHex(await sha256(textEncoder.encode("abc"))),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert.equal(
      encodeHex(
        await hmac(
          "SHA-256",
          textEncoder.encode("key"),
          textEncoder.encode("The quick brown fox jumps over the lazy dog")
        )
      ),
      "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    );
  });

  it("compares equal-length and different-length values safely", () => {
    assert.equal(
      constantTimeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2)),
      true
    );
    assert.equal(
      constantTimeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3)),
      false
    );
    assert.equal(
      constantTimeEqual(Uint8Array.of(1), Uint8Array.of(1, 0)),
      false
    );
  });

  it("signs and verifies ECDSA payloads", async () => {
    const key = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"]
    );
    if (!("privateKey" in key)) {
      throw new Error("Expected an ECDSA key pair.");
    }
    const data = textEncoder.encode("payload");
    const signature = await signEcdsa(key.privateKey, data, "SHA-256");

    assert.equal(
      await verifyEcdsa(key.publicKey, signature, data, "SHA-256"),
      true
    );
    assert.equal(
      await verifyEcdsa(
        key.publicKey,
        signature,
        textEncoder.encode("other"),
        "SHA-256"
      ),
      false
    );
  });
});
