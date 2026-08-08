import assert from "node:assert/strict";
import { test } from "node:test";

import {
  completeBrowserWebAuthn,
  resolveBrowserWebAuthn,
} from "./browser-webauthn.js";
import type { AuthRequest, AuthTransport } from "./types.js";

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

test("completes registration through the shared authentication transport", async () => {
  const requests: AuthRequest[] = [];
  const transport: AuthTransport = {
    async execute(request) {
      requests.push(request);
      if (request.action === "start_webauthn_registration") {
        return {
          status: "webauthn_challenge_required",
          challenge: {
            kind: "webauthn",
            continuationToken: "challenge-token",
            expiresAt: "2026-07-30T12:00:00.000Z",
            parameters: {
              ceremony: "registration",
              challenge: "AQ",
              rpId: "example.com",
              rpName: "Example",
              userId: "AQ",
              userName: "person@example.com",
              displayName: "Person",
              timeout: "300000",
              attestation: "none",
              algorithms: ["ES256"],
            },
          },
        };
      }
      return { status: "authenticated" };
    },
  };
  const publicKeyCredential = Object.getOwnPropertyDescriptor(
    globalThis,
    "PublicKeyCredential"
  );
  const navigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  Object.defineProperty(globalThis, "PublicKeyCredential", {
    configurable: true,
    value: function PublicKeyCredential() {},
  });
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      credentials: {
        async create() {
          return {
            id: "credential-id",
            response: {
              attestationObject: new Uint8Array([2]).buffer,
              clientDataJSON: new Uint8Array([1]).buffer,
              getTransports: () => ["internal"],
            },
          };
        },
      },
    },
  });

  try {
    assert.deepEqual(
      await completeBrowserWebAuthn(transport, "registration"),
      { status: "authenticated" }
    );
  } finally {
    restoreProperty("PublicKeyCredential", publicKeyCredential);
    restoreProperty("navigator", navigator);
  }

  assert.equal(requests.length, 2);
  assert.deepEqual(requests[0], { action: "start_webauthn_registration" });
  assert.deepEqual(requests[1], {
    action: "continue",
    continuationToken: "challenge-token",
    kind: "webauthn",
    values: {
      ceremony: "registration",
      challenge: "AQ",
      rpId: "example.com",
      rpName: "Example",
      userId: "AQ",
      userName: "person@example.com",
      displayName: "Person",
      timeout: "300000",
      attestation: "none",
      credential: JSON.stringify({
        credentialId: "credential-id",
        clientDataJSON: "AQ",
        attestationObject: "Ag",
        transports: ["internal"],
      }),
    },
  });
});

function restoreProperty(
  name: "PublicKeyCredential" | "navigator",
  descriptor: PropertyDescriptor | undefined
): void {
  if (descriptor) {
    Object.defineProperty(globalThis, name, descriptor);
  } else {
    Reflect.deleteProperty(globalThis, name);
  }
}
