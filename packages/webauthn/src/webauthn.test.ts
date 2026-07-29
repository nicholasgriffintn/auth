import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  AuthError,
  createAuth,
  hashSecret,
  type AuthChallengeRecord,
  type AuthSessionRecord,
  type AuthUser,
} from "@ngriffin_uk/auth-core";
import { sha256, toArrayBuffer } from "@ngriffin_uk/auth-crypto";
import {
  decodeBase64Url,
  encodeBase64Url,
} from "@ngriffin_uk/auth-encoding";

import { webAuthn } from "./plugin.js";
import type {
  WebAuthnAuthenticationResponse,
  WebAuthnCredential,
  WebAuthnRegistrationResponse,
} from "./types.js";

const textEncoder = new TextEncoder();
const RP_ID = "example.com";
const ORIGIN = "https://example.com";
const now = new Date("2026-01-01T00:00:00.000Z");
const user: AuthUser = {
  id: "user-1",
  email: "person@example.com",
  createdAt: now,
};

describe("WebAuthn middleware", () => {
  it("rejects insecure or RP-unrelated origins", () => {
    const store = {
      async saveCredential() {},
      async findCredential() {
        return null;
      },
      async listCredentials() {
        return [];
      },
      async updateSignCount() {
        return false;
      },
    };
    assert.throws(() =>
      webAuthn({
        rpId: "example.com",
        rpName: "Example",
        origins: ["http://example.com"],
        store,
      })
    );
    assert.throws(() =>
      webAuthn({
        rpId: "example.com",
        rpName: "Example",
        origins: ["https://attacker.test"],
        store,
      })
    );
    assert.doesNotThrow(() =>
      webAuthn({
        rpId: "example.com",
        rpName: "Example",
        origins: ["https://login.example.com"],
        store,
      })
    );
  });

  it("registers an attested ES256 credential and authenticates it", async () => {
    const fixture = await createFixture();
    const registration = await fixture.auth.providers.webauthn.startRegistration({
      userId: user.id,
      userName: user.email,
      displayName: "Person",
    });
    assert.equal(registration.status, "webauthn_challenge_required");
    if (registration.status !== "webauthn_challenge_required") return;

    const registered = await fixture.auth.providers.webauthn.finishRegistration({
      token: registration.challenge.continuationToken,
      response: await createRegistrationResponse(
        fixture.keys,
        registration.challenge.continuationToken
      ),
    });
    assert.equal(registered.status, "authenticated");
    assert.equal(fixture.credentials.size, 1);

    const authentication =
      await fixture.auth.providers.webauthn.startAuthentication(user.id);
    assert.equal(authentication.status, "webauthn_challenge_required");
    if (authentication.status !== "webauthn_challenge_required") return;
    const credential = [...fixture.credentials.values()][0]!;
    const authenticated =
      await fixture.auth.providers.webauthn.finishAuthentication({
        token: authentication.challenge.continuationToken,
        response: await createAuthenticationResponse(
          fixture.keys.privateKey,
          credential.id,
          authentication.challenge.continuationToken,
          1
        ),
      });

    assert.equal(authenticated.status, "authenticated");
    assert.equal(fixture.credentials.get(credential.id)?.signCount, 1);
  });

  it("rejects an origin mismatch", async () => {
    const fixture = await createFixture();
    const registration = await fixture.auth.providers.webauthn.startRegistration({
      userId: user.id,
      userName: user.email,
      displayName: "Person",
    });
    if (registration.status !== "webauthn_challenge_required") {
      assert.fail("Expected a registration challenge.");
    }
    const response = await createRegistrationResponse(
      fixture.keys,
      registration.challenge.continuationToken,
      "https://attacker.example"
    );

    await assert.rejects(
      fixture.auth.providers.webauthn.finishRegistration({
        token: registration.challenge.continuationToken,
        response,
      }),
      (error) =>
        error instanceof AuthError && error.code === "invalid_credentials"
    );
  });

  it("rejects a cloned or replayed signature counter", async () => {
    const fixture = await createFixture();
    await registerFixture(fixture);
    const first = await fixture.auth.providers.webauthn.startAuthentication();
    if (first.status !== "webauthn_challenge_required") {
      assert.fail("Expected an authentication challenge.");
    }
    const credential = [...fixture.credentials.values()][0]!;
    await fixture.auth.providers.webauthn.finishAuthentication({
      token: first.challenge.continuationToken,
      response: await createAuthenticationResponse(
        fixture.keys.privateKey,
        credential.id,
        first.challenge.continuationToken,
        1
      ),
    });
    const replay = await fixture.auth.providers.webauthn.startAuthentication();
    if (replay.status !== "webauthn_challenge_required") {
      assert.fail("Expected an authentication challenge.");
    }

    await assert.rejects(
      fixture.auth.providers.webauthn.finishAuthentication({
        token: replay.challenge.continuationToken,
        response: await createAuthenticationResponse(
          fixture.keys.privateKey,
          credential.id,
          replay.challenge.continuationToken,
          1
        ),
      }),
      (error) =>
        error instanceof AuthError && error.code === "invalid_credentials"
    );
  });
});

async function createFixture() {
  const challenges = new Map<string, AuthChallengeRecord>();
  const sessions = new Map<string, AuthSessionRecord>();
  const credentials = new Map<string, WebAuthnCredential>();
  const keys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const base = createAuth({
    users: {
      async findById(userId) {
        return userId === user.id ? user : null;
      },
    },
    sessions: {
      async create(record) {
        sessions.set(record.tokenHash, record);
      },
      async findByTokenHash(tokenHash) {
        return sessions.get(tokenHash) ?? null;
      },
      async deleteByTokenHash(tokenHash) {
        sessions.delete(tokenHash);
      },
    },
    challenges: {
      async create(record) {
        challenges.set(record.tokenHash, record);
      },
      async consumeByTokenHash(tokenHash) {
        const record = challenges.get(tokenHash) ?? null;
        challenges.delete(tokenHash);
        return record;
      },
    },
    clock: () => now,
  });
  const auth = base.use(
    webAuthn({
      rpId: RP_ID,
      rpName: "Example",
      origins: [ORIGIN],
      requireUserVerification: false,
      store: {
        async saveCredential(credential) {
          credentials.set(credential.id, credential);
        },
        async findCredential(credentialId) {
          return credentials.get(credentialId) ?? null;
        },
        async listCredentials(userId) {
          return [...credentials.values()].filter(
            (credential) => credential.userId === userId
          );
        },
        async updateSignCount(input) {
          const credential = credentials.get(input.credentialId);
          if (
            !credential ||
            credential.signCount !== input.previousSignCount
          ) {
            return false;
          }
          credentials.set(input.credentialId, {
            ...credential,
            signCount: input.signCount,
            backedUp: input.backedUp,
            updatedAt: now,
          });
          return true;
        },
      },
    })
  );
  return { auth, challenges, credentials, keys, sessions };
}

async function registerFixture(
  fixture: Awaited<ReturnType<typeof createFixture>>
): Promise<void> {
  const registration = await fixture.auth.providers.webauthn.startRegistration({
    userId: user.id,
    userName: user.email,
    displayName: "Person",
  });
  if (registration.status !== "webauthn_challenge_required") {
    assert.fail("Expected a registration challenge.");
  }
  await fixture.auth.providers.webauthn.finishRegistration({
    token: registration.challenge.continuationToken,
    response: await createRegistrationResponse(
      fixture.keys,
      registration.challenge.continuationToken
    ),
  });
}

async function createRegistrationResponse(
  keys: CryptoKeyPair,
  challenge: string,
  origin = ORIGIN
): Promise<WebAuthnRegistrationResponse> {
  const publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  if (!publicJwk.x || !publicJwk.y) {
    throw new Error("Expected an EC public key.");
  }
  const credentialId = crypto.getRandomValues(new Uint8Array(32));
  const coseKey = encodeCbor(
    new Map<TestCborKey, TestCborValue>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, decodeBase64Url(publicJwk.x)],
      [-3, decodeBase64Url(publicJwk.y)],
    ])
  );
  const authenticatorData = concat(
    await sha256(textEncoder.encode(RP_ID)),
    Uint8Array.of(0x41),
    uint32(0),
    new Uint8Array(16),
    uint16(credentialId.length),
    credentialId,
    coseKey
  );
  const attestationObject = encodeCbor(
    new Map<TestCborKey, TestCborValue>([
      ["fmt", "none"],
      ["authData", authenticatorData],
      ["attStmt", new Map()],
    ])
  );
  return {
    credentialId: encodeBase64Url(credentialId),
    clientDataJSON: createClientData("webauthn.create", challenge, origin),
    attestationObject: encodeBase64Url(attestationObject),
    transports: ["internal"],
  };
}

async function createAuthenticationResponse(
  privateKey: CryptoKey,
  credentialId: string,
  challenge: string,
  signCount: number
): Promise<WebAuthnAuthenticationResponse> {
  const clientDataJSON = createClientData(
    "webauthn.get",
    challenge,
    ORIGIN
  );
  const clientBytes = decodeBase64Url(clientDataJSON);
  const authenticatorData = concat(
    await sha256(textEncoder.encode(RP_ID)),
    Uint8Array.of(0x01),
    uint32(signCount)
  );
  const rawSignature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      toArrayBuffer(
        concat(authenticatorData, await sha256(clientBytes))
      )
    )
  );
  return {
    credentialId,
    clientDataJSON,
    authenticatorData: encodeBase64Url(authenticatorData),
    signature: encodeBase64Url(ecdsaRawToDer(rawSignature)),
  };
}

function createClientData(
  type: "webauthn.create" | "webauthn.get",
  challenge: string,
  origin: string
): string {
  return encodeBase64Url(
    textEncoder.encode(
      JSON.stringify({
        type,
        challenge: encodeBase64Url(textEncoder.encode(challenge)),
        origin,
        crossOrigin: false,
      })
    )
  );
}

type TestCborKey = number | string;
type TestCborValue =
  | number
  | string
  | Uint8Array
  | ReadonlyMap<TestCborKey, TestCborValue>;

function encodeCbor(value: TestCborValue): Uint8Array {
  if (typeof value === "number") {
    return value >= 0
      ? encodeCborLength(0, value)
      : encodeCborLength(1, -1 - value);
  }
  if (typeof value === "string") {
    const bytes = textEncoder.encode(value);
    return concat(encodeCborLength(3, bytes.length), bytes);
  }
  if (value instanceof Uint8Array) {
    return concat(encodeCborLength(2, value.length), value);
  }
  const entries: Uint8Array[] = [];
  for (const [key, item] of value) {
    entries.push(encodeCbor(key), encodeCbor(item));
  }
  return concat(encodeCborLength(5, value.size), ...entries);
}

function encodeCborLength(major: number, value: number): Uint8Array {
  if (value < 24) return Uint8Array.of((major << 5) | value);
  if (value < 256) return Uint8Array.of((major << 5) | 24, value);
  return concat(Uint8Array.of((major << 5) | 25), uint16(value));
}

function uint16(value: number): Uint8Array {
  const bytes = new Uint8Array(2);
  new DataView(bytes.buffer).setUint16(0, value);
  return bytes;
}

function uint32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(
    parts.reduce((length, part) => length + part.length, 0)
  );
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function ecdsaRawToDer(signature: Uint8Array): Uint8Array {
  const coordinateSize = signature.length / 2;
  const r = derInteger(signature.slice(0, coordinateSize));
  const s = derInteger(signature.slice(coordinateSize));
  const length = r.length + s.length;
  return concat(Uint8Array.of(0x30, length), r, s);
}

function derInteger(bytes: Uint8Array): Uint8Array {
  let first = 0;
  while (first < bytes.length - 1 && bytes[first] === 0) first += 1;
  const value = bytes.slice(first);
  const padding = (value[0]! & 0x80) === 0 ? new Uint8Array() : Uint8Array.of(0);
  return concat(Uint8Array.of(0x02, value.length + padding.length), padding, value);
}
