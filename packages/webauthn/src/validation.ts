import { constantTimeEqual, requireSubtle, sha256, toArrayBuffer } from "@ngriffin_uk/auth-crypto";
import { decodeBase64Url, encodeBase64Url } from "@ngriffin_uk/auth-encoding";

import {
  cborBytes,
  cborMap,
  cborNumber,
  cborString,
  decodeCbor,
  decodeFirstCbor,
  type CborValue,
} from "./cbor.js";
import { ecdsaDerToRaw } from "./der.js";
import type {
  ParsedAuthenticatorData,
  WebAuthnAlgorithm,
  WebAuthnAuthenticationResponse,
  WebAuthnRegistrationResponse,
} from "./types.js";

const textEncoder = new TextEncoder();
const MAX_ATTESTATION_BYTES = 1024 * 1024;
const MAX_CLIENT_DATA_BYTES = 64 * 1024;
const MAX_CREDENTIAL_ID_BYTES = 8 * 1024;
const MAX_SIGNATURE_BYTES = 16 * 1024;
const USER_PRESENT = 0x01;
const USER_VERIFIED = 0x04;
const BACKUP_ELIGIBLE = 0x08;
const BACKED_UP = 0x10;
const ATTESTED_CREDENTIAL_DATA = 0x40;
const EXTENSION_DATA = 0x80;
const RESERVED_FLAGS = 0x22;

interface ValidationOptions {
  readonly challenge: string;
  readonly rpId: string;
  readonly origins: readonly string[];
  readonly requireUserVerification?: boolean;
}

export async function validateRegistration(
  response: WebAuthnRegistrationResponse,
  options: ValidationOptions
): Promise<ParsedAuthenticatorData> {
  const clientData = await validateClientData(
    response.clientDataJSON,
    "webauthn.create",
    options
  );
  const attestation = cborMap(
    decodeCbor(
      decodeBoundedBase64Url(
        response.attestationObject,
        MAX_ATTESTATION_BYTES,
        "attestation object"
      )
    ),
    "attestationObject"
  );
  const format = cborString(attestation.get("fmt"), "fmt");
  const authenticatorData = cborBytes(attestation.get("authData"), "authData");
  const statement = cborMap(attestation.get("attStmt"), "attStmt");
  const parsed = await parseAuthenticatorData(authenticatorData, options, true);
  if (
    !parsed.credentialId ||
    !parsed.credentialPublicKey ||
    !parsed.algorithm ||
    !constantTimeEqual(
      parsed.credentialId,
      decodeBoundedBase64Url(
        response.credentialId,
        MAX_CREDENTIAL_ID_BYTES,
        "credential ID"
      )
    )
  ) {
    throw new TypeError("The attested credential does not match the response.");
  }

  if (format === "none") {
    if (statement.size !== 0) {
      throw new TypeError("None attestation must have an empty statement.");
    }
  } else if (format === "packed") {
    if (statement.has("x5c")) {
      throw new TypeError("Certificate attestation is not supported.");
    }
    const algorithm = cborNumber(statement.get("alg"), "attStmt.alg");
    const signature = cborBytes(statement.get("sig"), "attStmt.sig");
    if (algorithm !== coseAlgorithm(parsed.algorithm)) {
      throw new TypeError("Attestation algorithm does not match the credential.");
    }
    const data = concat(authenticatorData, clientData.hash);
    if (
      !(await verifySignature(
        parsed.publicKeyOrThrow(),
        parsed.algorithm,
        signature,
        data
      ))
    ) {
      throw new TypeError("The attestation signature is invalid.");
    }
  } else {
    throw new TypeError(`Unsupported attestation format: ${format}`);
  }
  return parsed;
}

export async function validateAuthentication(
  response: WebAuthnAuthenticationResponse,
  options: ValidationOptions & {
    readonly publicKeyJwk: JsonWebKey;
    readonly algorithm: WebAuthnAlgorithm;
  }
): Promise<ParsedAuthenticatorData> {
  const clientData = await validateClientData(
    response.clientDataJSON,
    "webauthn.get",
    options
  );
  const authenticatorData = decodeBoundedBase64Url(
    response.authenticatorData,
    MAX_ATTESTATION_BYTES,
    "authenticator data"
  );
  const parsed = await parseAuthenticatorData(authenticatorData, options, false);
  const key = await importCredentialKey(
    options.publicKeyJwk,
    options.algorithm
  );
  const valid = await verifySignature(
    key,
    options.algorithm,
    decodeBoundedBase64Url(
      response.signature,
      MAX_SIGNATURE_BYTES,
      "signature"
    ),
    concat(authenticatorData, clientData.hash)
  );
  if (!valid) throw new TypeError("The assertion signature is invalid.");
  return parsed;
}

async function validateClientData(
  encoded: string,
  expectedType: "webauthn.create" | "webauthn.get",
  options: ValidationOptions
): Promise<{ readonly hash: Uint8Array }> {
  const bytes = decodeBoundedBase64Url(
    encoded,
    MAX_CLIENT_DATA_BYTES,
    "client data"
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new TypeError("Client data is not valid JSON.");
  }
  if (!isRecord(parsed)) throw new TypeError("Client data must be an object.");
  if (parsed["type"] !== expectedType) {
    throw new TypeError("WebAuthn ceremony type does not match.");
  }
  if (typeof parsed["challenge"] !== "string") {
    throw new TypeError("WebAuthn challenge is missing.");
  }
  const actualChallenge = decodeBoundedBase64Url(
    parsed["challenge"],
    1024,
    "challenge"
  );
  if (
    !constantTimeEqual(
      actualChallenge,
      textEncoder.encode(options.challenge)
    )
  ) {
    throw new TypeError("WebAuthn challenge does not match.");
  }
  if (
    typeof parsed["origin"] !== "string" ||
    !options.origins.includes(parsed["origin"])
  ) {
    throw new TypeError("WebAuthn origin does not match.");
  }
  if (parsed["crossOrigin"] === true) {
    throw new TypeError("Cross-origin WebAuthn ceremonies are not accepted.");
  }
  return { hash: await sha256(bytes) };
}

async function parseAuthenticatorData(
  bytes: Uint8Array,
  options: ValidationOptions,
  registration: boolean
): Promise<ParsedAuthenticatorData & { publicKeyOrThrow(): CryptoKey }> {
  if (bytes.length < 37) throw new TypeError("Authenticator data is truncated.");
  const expectedRpIdHash = await sha256(textEncoder.encode(options.rpId));
  if (!constantTimeEqual(bytes.slice(0, 32), expectedRpIdHash)) {
    throw new TypeError("Authenticator RP ID does not match.");
  }
  const flags = bytes[32]!;
  if ((flags & RESERVED_FLAGS) !== 0) {
    throw new TypeError("Authenticator data contains reserved flags.");
  }
  if ((flags & USER_PRESENT) === 0) {
    throw new TypeError("Authenticator did not verify user presence.");
  }
  if (options.requireUserVerification && (flags & USER_VERIFIED) === 0) {
    throw new TypeError("Authenticator did not verify the user.");
  }
  const backupEligible = (flags & BACKUP_ELIGIBLE) !== 0;
  const backedUp = (flags & BACKED_UP) !== 0;
  if (backedUp && !backupEligible) {
    throw new TypeError("Authenticator backup flags are inconsistent.");
  }
  const signCount = new DataView(
    bytes.buffer,
    bytes.byteOffset + 33,
    4
  ).getUint32(0);
  let credentialId: Uint8Array | undefined;
  let credentialPublicKey: JsonWebKey | undefined;
  let algorithm: WebAuthnAlgorithm | undefined;
  let importedKey: CryptoKey | undefined;
  let dataEnd = 37;

  if (registration) {
    if ((flags & ATTESTED_CREDENTIAL_DATA) === 0 || bytes.length < 56) {
      throw new TypeError("Attested credential data is missing.");
    }
    const credentialIdLength = new DataView(
      bytes.buffer,
      bytes.byteOffset + 53,
      2
    ).getUint16(0);
    const credentialStart = 55;
    const credentialEnd = credentialStart + credentialIdLength;
    if (credentialIdLength === 0 || credentialEnd >= bytes.length) {
      throw new TypeError("Attested credential ID is malformed.");
    }
    credentialId = bytes.slice(credentialStart, credentialEnd);
    const decodedKey = decodeFirstCbor(bytes.slice(credentialEnd));
    const cose = cborMap(decodedKey.value, "credentialPublicKey");
    dataEnd = credentialEnd + decodedKey.bytesRead;
    const converted = coseKeyToJwk(cose);
    credentialPublicKey = converted.jwk;
    algorithm = converted.algorithm;
    importedKey = await importCredentialKey(credentialPublicKey, algorithm);
  } else if ((flags & ATTESTED_CREDENTIAL_DATA) !== 0) {
    throw new TypeError("Authentication data contains attested credentials.");
  }

  if ((flags & EXTENSION_DATA) !== 0) {
    cborMap(decodeCbor(bytes.slice(dataEnd)), "authenticatorExtensions");
  } else if (dataEnd !== bytes.length) {
    throw new TypeError("Authenticator data contains trailing bytes.");
  }

  return {
    bytes,
    flags,
    signCount,
    backupEligible,
    backedUp,
    ...(credentialId ? { credentialId } : {}),
    ...(credentialPublicKey ? { credentialPublicKey } : {}),
    ...(algorithm ? { algorithm } : {}),
    publicKeyOrThrow() {
      if (!importedKey) throw new TypeError("Credential key is missing.");
      return importedKey;
    },
  };
}

function coseKeyToJwk(
  cose: ReadonlyMap<unknown, CborValue>
): { readonly jwk: JsonWebKey; readonly algorithm: WebAuthnAlgorithm } {
  const keyType = cborNumber(cose.get(1), "credentialPublicKey.kty");
  const algorithm = cborNumber(cose.get(3), "credentialPublicKey.alg");
  if (keyType === 2 && algorithm === -7) {
    if (cborNumber(cose.get(-1), "credentialPublicKey.crv") !== 1) {
      throw new TypeError("Only the P-256 credential curve is supported.");
    }
    const x = cborBytes(cose.get(-2), "credentialPublicKey.x");
    const y = cborBytes(cose.get(-3), "credentialPublicKey.y");
    if (x.length !== 32 || y.length !== 32) {
      throw new TypeError("P-256 coordinates must be 32 bytes.");
    }
    return {
      algorithm: "ES256",
      jwk: {
        kty: "EC",
        crv: "P-256",
        x: encodeBase64Url(x),
        y: encodeBase64Url(y),
        alg: "ES256",
        ext: true,
      },
    };
  }
  if (keyType === 3 && algorithm === -257) {
    const encodedModulus = cborBytes(cose.get(-1), "credentialPublicKey.n");
    let firstNonZero = 0;
    while (
      firstNonZero < encodedModulus.length &&
      encodedModulus[firstNonZero] === 0
    ) {
      firstNonZero += 1;
    }
    const modulus = encodedModulus.slice(firstNonZero);
    const exponent = cborBytes(cose.get(-2), "credentialPublicKey.e");
    if (
      modulus.length < 256 ||
      (modulus.length === 256 && (modulus[0] ?? 0) < 0x80) ||
      exponent.length === 0 ||
      exponent.length > 8
    ) {
      throw new TypeError("RSA credential key is too small or malformed.");
    }
    return {
      algorithm: "RS256",
      jwk: {
        kty: "RSA",
        n: encodeBase64Url(modulus),
        e: encodeBase64Url(exponent),
        alg: "RS256",
        ext: true,
      },
    };
  }
  throw new TypeError("Credential key algorithm is not supported.");
}

async function importCredentialKey(
  jwk: JsonWebKey,
  algorithm: WebAuthnAlgorithm
): Promise<CryptoKey> {
  return requireSubtle().importKey(
    "jwk",
    jwk,
    algorithm === "ES256"
      ? { name: "ECDSA", namedCurve: "P-256" }
      : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

async function verifySignature(
  key: CryptoKey,
  algorithm: WebAuthnAlgorithm,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  const normalised =
    algorithm === "ES256" ? ecdsaDerToRaw(signature, 32) : signature;
  return requireSubtle().verify(
    algorithm === "ES256"
      ? { name: "ECDSA", hash: "SHA-256" }
      : "RSASSA-PKCS1-v1_5",
    key,
    toArrayBuffer(normalised),
    toArrayBuffer(data)
  );
}

function coseAlgorithm(algorithm: WebAuthnAlgorithm): number {
  return algorithm === "ES256" ? -7 : -257;
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeBoundedBase64Url(
  value: string,
  maxBytes: number,
  field: string
): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > Math.ceil((maxBytes * 4) / 3) + 2
  ) {
    throw new TypeError(`WebAuthn ${field} size is invalid.`);
  }
  const bytes = decodeBase64Url(value);
  if (bytes.length > maxBytes) {
    throw new TypeError(`WebAuthn ${field} size is invalid.`);
  }
  return bytes;
}
