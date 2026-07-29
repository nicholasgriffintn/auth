import assert from "node:assert/strict";
import { test } from "node:test";

import { encodeBase64Url } from "@ngriffin_uk/auth-encoding";

import {
  createWebAuthnAuthenticationOptions,
  createWebAuthnRegistrationOptions,
} from "../src/lib/webauthn.ts";

test("WebAuthn package challenges become browser registration options", () => {
  const options = createWebAuthnRegistrationOptions({
    kind: "webauthn",
    continuationToken: "continuation",
    expiresAt: "2026-01-01T00:10:00.000Z",
    parameters: {
      ceremony: "registration",
      challenge: "opaque-challenge",
      rpId: "example.com",
      rpName: "Example",
      userId: encodeBase64Url(new TextEncoder().encode("user-1")),
      userName: "person@example.com",
      displayName: "Person",
      timeout: "300000",
      attestation: "none",
      algorithms: ["ES256", "RS256"],
    },
  });

  assert.deepEqual(options.rp, { id: "example.com", name: "Example" });
  assert.deepEqual(options.user.name, "person@example.com");
  assert.deepEqual(
    options.pubKeyCredParams.map(({ alg }) => alg),
    [-7, -257],
  );
  assert.equal(options.authenticatorSelection?.userVerification, "required");
  assert.equal(
    new TextDecoder().decode(options.challenge),
    "opaque-challenge",
  );
});

test("WebAuthn registration options reject incomplete challenges", () => {
  assert.throws(
    () =>
      createWebAuthnRegistrationOptions({
        kind: "webauthn",
        continuationToken: "continuation",
        expiresAt: "2026-01-01T00:10:00.000Z",
        parameters: { ceremony: "registration" },
      }),
    /passkey/u,
  );
});

test("WebAuthn assertion options prefer the registered credential", () => {
  const credentialId = encodeBase64Url(new Uint8Array([1, 2, 3]));
  const options = createWebAuthnAuthenticationOptions({
    kind: "webauthn",
    continuationToken: "continuation",
    expiresAt: "2026-01-01T00:10:00.000Z",
    parameters: {
      ceremony: "authentication",
      challenge: "opaque-challenge",
      rpId: "example.com",
      timeout: "300000",
      userVerification: "required",
      allowCredentialIds: [credentialId],
    },
  });

  assert.equal(options.rpId, "example.com");
  assert.equal(options.userVerification, "required");
  assert.equal(options.allowCredentials?.length, 1);
  const allowedCredential = options.allowCredentials?.[0];
  assert.ok(allowedCredential);
  assert.deepEqual(
    new Uint8Array(allowedCredential.id),
    new Uint8Array([1, 2, 3]),
  );
});
