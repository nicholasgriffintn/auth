import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createRemoteJwksResolver,
  JwtError,
  type JwtJsonWebKey,
} from "./index.js";

describe("remote JWKS", () => {
  it("caches keys and refuses insecure endpoints", async () => {
    let requests = 0;
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: Uint8Array.of(1, 0, 1),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );
    if (!("publicKey" in keyPair)) throw new Error("Expected key pair.");
    const exportedJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const jwk: JwtJsonWebKey = {
      ...exportedJwk,
      kid: "key-1",
      alg: "RS256",
      use: "sig",
    };

    const resolver = createRemoteJwksResolver({
      url: "https://issuer.example/.well-known/jwks.json",
      fetch: async () => {
        requests += 1;
        return new Response(JSON.stringify({ keys: [jwk] }), {
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": "max-age=300",
          },
        });
      },
    });

    assert.ok(await resolver({ alg: "RS256", kid: "key-1" }));
    assert.ok(await resolver({ alg: "RS256", kid: "key-1" }));
    assert.equal(requests, 1);
    assert.throws(
      () => createRemoteJwksResolver({ url: "http://issuer.example/jwks" }),
      (error) => error instanceof JwtError && error.code === "invalid_key"
    );
  });

  it("bounds response size before accepting keys", async () => {
    const resolver = createRemoteJwksResolver({
      url: "https://issuer.example/jwks",
      maxResponseBytes: 10,
      fetch: async () =>
        new Response(JSON.stringify({ keys: [{ kty: "RSA" }] })),
    });

    await assert.rejects(
      async () => resolver({ alg: "RS256", kid: "key-1" }),
      (error: unknown) =>
        error instanceof JwtError && error.code === "invalid_key"
    );
  });

  it("rejects invalid cache clocks before making a request", async () => {
    let requested = false;
    const resolver = createRemoteJwksResolver({
      url: "https://issuer.example/jwks",
      clock: () => new Date(Number.NaN),
      fetch: async () => {
        requested = true;
        return new Response("{}");
      },
    });

    await assert.rejects(
      async () => resolver({ alg: "RS256", kid: "key-1" }),
      (error: unknown) =>
        error instanceof JwtError && error.code === "invalid_key"
    );
    assert.equal(requested, false);
  });
});
