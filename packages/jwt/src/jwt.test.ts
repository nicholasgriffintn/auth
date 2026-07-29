import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { JwtError, parseJwt, signJwt, verifyJwt } from "./index.js";

const textEncoder = new TextEncoder();

async function createHmacKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    textEncoder.encode("a sufficiently long test secret"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

describe("JWT", () => {
  it("rejects non-string tokens and invalid clocks as JWT errors", async () => {
    assert.throws(
      () => Reflect.apply(parseJwt, undefined, [42]),
      (error) =>
        error instanceof JwtError && error.code === "malformed_token"
    );
    const key = await createHmacKey();
    const token = await signJwt({}, { algorithm: "HS256", key });
    await assert.rejects(
      verifyJwt(token, {
        algorithms: ["HS256"],
        key,
        clock: () => new Date(Number.NaN),
      }),
      (error) =>
        error instanceof JwtError &&
        error.code === "claim_validation_failed"
    );
  });

  it("signs and validates allowed algorithms and claims", async () => {
    const key = await createHmacKey();
    const token = await signJwt(
      {
        sub: "user-1",
        iss: "https://issuer.example",
        aud: "client-1",
        iat: 1_767_225_600,
        exp: 1_767_225_900,
      },
      { algorithm: "HS256", key }
    );

    const claims = await verifyJwt(token, {
      algorithms: ["HS256"],
      key,
      issuer: "https://issuer.example",
      audience: "client-1",
      clock: () => new Date("2026-01-01T00:01:00.000Z"),
      maxTokenAgeSeconds: 120,
    });
    assert.equal(claims.sub, "user-1");
  });

  it("rejects tampering, expiry, and algorithms outside the allow-list", async () => {
    const key = await createHmacKey();
    const token = await signJwt(
      { sub: "user-1", exp: 1_767_225_600 },
      { algorithm: "HS256", key }
    );
    const segments = token.split(".");
    const tampered = `${segments[0]}.${segments[1]}A.${segments[2]}`;

    await assert.rejects(
      verifyJwt(tampered, { algorithms: ["HS256"], key }),
      (error) =>
        error instanceof JwtError &&
        ["invalid_signature", "malformed_token"].includes(error.code)
    );
    await assert.rejects(
      verifyJwt(token, {
        algorithms: ["HS256"],
        key,
        clock: () => new Date("2026-01-01T00:00:01.000Z"),
      }),
      (error) =>
        error instanceof JwtError &&
        error.code === "claim_validation_failed"
    );
    await assert.rejects(
      verifyJwt(token, { algorithms: ["HS512"], key }),
      (error) =>
        error instanceof JwtError && error.code === "disallowed_algorithm"
    );
  });

  it("rejects oversized tokens and future issued-at claims", async () => {
    assert.throws(
      () => parseJwt(`a.${"b".repeat(131_072)}.c`),
      (error) =>
        error instanceof JwtError && error.code === "malformed_token"
    );

    const key = await createHmacKey();
    const token = await signJwt(
      { iat: 1_767_225_660, exp: 1_767_226_000 },
      { algorithm: "HS256", key }
    );
    await assert.rejects(
      verifyJwt(token, {
        algorithms: ["HS256"],
        key,
        clock: () => new Date("2026-01-01T00:00:00.000Z"),
      }),
      (error) =>
        error instanceof JwtError &&
        error.code === "claim_validation_failed"
    );
  });

  it("rejects keys whose cryptographic parameters disagree with alg", async () => {
    const sha256Key = await createHmacKey();

    await assert.rejects(
      signJwt(
        { sub: "user-1" },
        { algorithm: "HS512", key: sha256Key }
      ),
      (error) =>
        error instanceof JwtError && error.code === "invalid_key"
    );

    const validToken = await signJwt(
      { sub: "user-1" },
      { algorithm: "HS256", key: sha256Key }
    );
    const [encodedHeader, encodedClaims, encodedSignature] =
      validToken.split(".");
    assert.ok(encodedHeader && encodedClaims && encodedSignature);
    const mismatchedHeader = Buffer.from(
      JSON.stringify({ typ: "JWT", alg: "HS512" })
    ).toString("base64url");

    await assert.rejects(
      verifyJwt(
        `${mismatchedHeader}.${encodedClaims}.${encodedSignature}`,
        { algorithms: ["HS512"], key: sha256Key }
      ),
      (error) =>
        error instanceof JwtError && error.code === "invalid_key"
    );
  });

  it("rejects unsupported critical JWS header parameters", async () => {
    const key = await createHmacKey();
    await assert.rejects(
      signJwt(
        { sub: "user-1" },
        {
          algorithm: "HS256",
          key,
          header: { crit: ["b64"], b64: false },
        }
      ),
      (error) =>
        error instanceof JwtError && error.code === "malformed_token"
    );
  });
});
