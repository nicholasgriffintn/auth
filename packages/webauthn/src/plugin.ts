import {
  AuthError,
  requireValidDate,
  type AuthFlowResult,
  type AuthPlugin,
  type AuthPluginContext,
  type AuthUser,
} from "@ngriffin_uk/auth-core";
import { decodeBase64Url, encodeBase64Url } from "@ngriffin_uk/auth-encoding";

import type {
  WebAuthnAuthenticationResponse,
  WebAuthnOperations,
  WebAuthnPluginConfig,
  WebAuthnRegistrationResponse,
} from "./types.js";
import {
  validateAuthentication,
  validateRegistration,
} from "./validation.js";

const textEncoder = new TextEncoder();
const MAX_CREDENTIALS_PER_USER = 100;

export function webAuthn<User extends AuthUser>(
  config: WebAuthnPluginConfig
): AuthPlugin<"webauthn", WebAuthnOperations<User>, User> {
  validateConfig(config);
  return {
    name: "webauthn",
    install(context) {
      return {
        startRegistration: (input) =>
          startRegistration(context, config, input),
        finishRegistration: (input) =>
          finishRegistration(context, config, input.token, input.response),
        startAuthentication: (userId) =>
          startAuthentication(context, config, userId),
        finishAuthentication: (input) =>
          finishAuthentication(context, config, input.token, input.response),
      };
    },
  };
}

async function startRegistration<User extends AuthUser>(
  context: AuthPluginContext<User>,
  config: WebAuthnPluginConfig,
  input: {
    readonly userId: string;
    readonly userName: string;
    readonly displayName: string;
  }
): Promise<AuthFlowResult<User>> {
  const userIdBytes = validateUserId(input.userId);
  if (
    !isValidDisplayName(input.userName) ||
    !isValidDisplayName(input.displayName)
  ) {
    throw new AuthError("invalid_input", "WebAuthn user names are invalid.");
  }
  const user = await context.users.findById(input.userId);
  if (!user) throw new AuthError("invalid_input");
  const issued = await context.issueChallenge("webauthn", "webauthn", {
    ceremony: "registration",
    userId: input.userId,
  });
  return challengeResult(issued, {
    ceremony: "registration",
    challenge: issued.token,
    rpId: config.rpId,
    rpName: config.rpName,
    userId: encodeBase64Url(userIdBytes),
    userName: input.userName,
    displayName: input.displayName,
    timeout: String(config.timeoutMs ?? 300_000),
    attestation: config.attestation ?? "none",
    algorithms: ["ES256", "RS256"],
  });
}

async function finishRegistration<User extends AuthUser>(
  context: AuthPluginContext<User>,
  config: WebAuthnPluginConfig,
  token: string,
  response: WebAuthnRegistrationResponse
): Promise<AuthFlowResult<User>> {
  const challenge = await context.consumeChallenge(token, "webauthn", [
    "webauthn",
  ]);
  requireCeremony(challenge.payload, "registration");
  const userId = payloadString(challenge.payload, "userId");
  let parsed;
  let transports: readonly AuthenticatorTransport[] | undefined;
  try {
    parsed = await validateRegistration(response, {
      challenge: token,
      rpId: config.rpId,
      origins: config.origins,
      ...(config.requireUserVerification === undefined
        ? {}
        : { requireUserVerification: config.requireUserVerification }),
    });
    transports = validateTransports(response.transports);
  } catch (cause) {
    throw new AuthError("invalid_credentials", "The passkey registration is invalid.", {
      cause,
    });
  }
  if (
    !parsed.credentialId ||
    !parsed.credentialPublicKey ||
    !parsed.algorithm
  ) {
    throw new AuthError(
      "invalid_credentials",
      "The passkey registration is incomplete."
    );
  }
  const timestamp = requireValidDate(
    context.now(),
    "WebAuthn clock"
  );
  await config.store.saveCredential({
    id: encodeBase64Url(parsed.credentialId),
    userId,
    publicKeyJwk: parsed.credentialPublicKey,
    algorithm: parsed.algorithm,
    signCount: parsed.signCount,
    ...(transports ? { transports } : {}),
    backupEligible: parsed.backupEligible,
    backedUp: parsed.backedUp,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  return authenticated(context, userId);
}

async function startAuthentication<User extends AuthUser>(
  context: AuthPluginContext<User>,
  config: WebAuthnPluginConfig,
  userId?: string
): Promise<AuthFlowResult<User>> {
  if (userId !== undefined) {
    validateUserId(userId);
    if (!(await context.users.findById(userId))) {
      throw new AuthError("invalid_input");
    }
  }
  const credentials = userId
    ? await config.store.listCredentials(userId)
    : [];
  if (credentials.length > MAX_CREDENTIALS_PER_USER) {
    throw new AuthError(
      "storage_error",
      "Too many WebAuthn credentials are stored for this user."
    );
  }
  const allowCredentialIds = credentials.map((credential) => {
    if (credential.userId !== userId) {
      throw new AuthError(
        "storage_error",
        "A WebAuthn credential is assigned to the wrong user."
      );
    }
    try {
      return canonicalCredentialId(credential.id);
    } catch (cause) {
      throw new AuthError(
        "storage_error",
        "A stored WebAuthn credential ID is invalid.",
        { cause }
      );
    }
  });
  const issued = await context.issueChallenge("webauthn", "webauthn", {
    ceremony: "authentication",
    ...(userId ? { userId } : {}),
  });
  return challengeResult(issued, {
    ceremony: "authentication",
    challenge: issued.token,
    rpId: config.rpId,
    timeout: String(config.timeoutMs ?? 300_000),
    userVerification: config.requireUserVerification ? "required" : "preferred",
    ...(allowCredentialIds.length > 0
      ? { allowCredentialIds }
      : {}),
  });
}

function validateUserId(value: string): Uint8Array {
  if (typeof value !== "string") {
    throw new AuthError("invalid_input", "The WebAuthn user ID is invalid.");
  }
  const bytes = textEncoder.encode(value);
  if (bytes.length === 0 || bytes.length > 64) {
    throw new AuthError(
      "invalid_input",
      "The WebAuthn user ID must be between 1 and 64 bytes."
    );
  }
  return bytes;
}

async function finishAuthentication<User extends AuthUser>(
  context: AuthPluginContext<User>,
  config: WebAuthnPluginConfig,
  token: string,
  response: WebAuthnAuthenticationResponse
): Promise<AuthFlowResult<User>> {
  const challenge = await context.consumeChallenge(token, "webauthn", [
    "webauthn",
  ]);
  requireCeremony(challenge.payload, "authentication");
  const credentialId = canonicalCredentialId(response.credentialId);
  const credential = await config.store.findCredential(credentialId);
  if (!credential) throw new AuthError("invalid_credentials");
  const expectedUserId = optionalPayloadString(challenge.payload, "userId");
  if (expectedUserId && credential.userId !== expectedUserId) {
    throw new AuthError("challenge_mismatch");
  }
  if (
    response.userHandle &&
    !constantUserHandle(response.userHandle, credential.userId)
  ) {
    throw new AuthError("invalid_credentials");
  }
  let parsed;
  try {
    parsed = await validateAuthentication(response, {
      challenge: token,
      rpId: config.rpId,
      origins: config.origins,
      ...(config.requireUserVerification === undefined
        ? {}
        : { requireUserVerification: config.requireUserVerification }),
      publicKeyJwk: credential.publicKeyJwk,
      algorithm: credential.algorithm,
    });
  } catch (cause) {
    throw new AuthError("invalid_credentials", "The passkey assertion is invalid.", {
      cause,
    });
  }
  const counterSupported =
    credential.signCount !== 0 || parsed.signCount !== 0;
  if (parsed.backupEligible !== credential.backupEligible) {
    throw new AuthError(
      "invalid_credentials",
      "The passkey backup eligibility changed."
    );
  }
  if (
    counterSupported &&
    parsed.signCount <= credential.signCount
  ) {
    throw new AuthError("invalid_credentials", "The passkey assertion was replayed.");
  }
  if (
    !(await config.store.updateSignCount({
      credentialId,
      previousSignCount: credential.signCount,
      signCount: parsed.signCount,
      backedUp: parsed.backedUp,
    }))
  ) {
    throw new AuthError("invalid_credentials", "The passkey assertion was replayed.");
  }
  return authenticated(context, credential.userId);
}

function challengeResult<User extends AuthUser>(
  issued: { readonly token: string; readonly expiresAt: Date },
  parameters: Readonly<Record<string, string | readonly string[]>>
): AuthFlowResult<User> {
  return {
    status: "webauthn_challenge_required",
    challenge: {
      kind: "webauthn",
      continuationToken: issued.token,
      expiresAt: issued.expiresAt,
      parameters,
    },
  };
}

async function authenticated<User extends AuthUser>(
  context: AuthPluginContext<User>,
  userId: string
): Promise<AuthFlowResult<User>> {
  const user = await context.users.findById(userId);
  if (!user) throw new AuthError("challenge_expired");
  const session = await context.issueSession(userId);
  return {
    status: "authenticated",
    session: { user, token: session.token, expiresAt: session.expiresAt },
  };
}

function validateConfig(config: WebAuthnPluginConfig): void {
  if (
    !isValidRpId(config.rpId) ||
    !isValidDisplayName(config.rpName) ||
    !Array.isArray(config.origins) ||
    config.origins.length === 0 ||
    config.origins.length > 20 ||
    config.origins.some((origin) => !isValidOrigin(origin, config.rpId)) ||
    (config.timeoutMs !== undefined &&
      (!Number.isSafeInteger(config.timeoutMs) ||
        config.timeoutMs < 1 ||
        config.timeoutMs > 600_000))
  ) {
    throw new TypeError("WebAuthn configuration is invalid.");
  }
}

function isValidDisplayName(value: string): boolean {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    textEncoder.encode(value).length <= 256
  );
}

function validateTransports(
  values: readonly AuthenticatorTransport[] | undefined
): readonly AuthenticatorTransport[] | undefined {
  if (values === undefined) return undefined;
  if (!Array.isArray(values) || values.length > 6) {
    throw new TypeError("WebAuthn transports are invalid.");
  }
  const transports = values.map(validateTransport);
  if (new Set(transports).size !== transports.length) {
    throw new TypeError("WebAuthn transports must be unique.");
  }
  return transports;
}

function validateTransport(value: unknown): AuthenticatorTransport {
  switch (value) {
    case "ble":
    case "hybrid":
    case "internal":
    case "nfc":
    case "usb":
      return value;
    default:
      throw new TypeError("WebAuthn transport is invalid.");
  }
}

function canonicalCredentialId(value: string): string {
  try {
    if (value.length === 0 || value.length > 16_384) {
      throw new TypeError("Credential ID size is invalid.");
    }
    return encodeBase64Url(decodeBase64Url(value));
  } catch {
    throw new AuthError("invalid_credentials");
  }
}

function constantUserHandle(encoded: string, userId: string): boolean {
  try {
    if (encoded.length === 0 || encoded.length > 128) return false;
    const actual = decodeBase64Url(encoded);
    const expected = textEncoder.encode(userId);
    if (actual.length !== expected.length) return false;
    let difference = 0;
    for (let index = 0; index < actual.length; index += 1) {
      difference |= actual[index]! ^ expected[index]!;
    }
    return difference === 0;
  } catch {
    return false;
  }
}

function isValidRpId(value: string): boolean {
  if (
    !value ||
    value !== value.toLowerCase() ||
    value.endsWith(".") ||
    /[/:@?#\s]/u.test(value)
  ) {
    return false;
  }
  try {
    const parsed = new URL(`https://${value}`);
    return parsed.hostname === value && parsed.pathname === "/";
  } catch {
    return false;
  }
}

function isValidOrigin(value: string, rpId: string): boolean {
  try {
    const parsed = new URL(value);
    const hostname = parsed.hostname.toLowerCase();
    const localHttp =
      parsed.protocol === "http:" &&
      ["127.0.0.1", "localhost", "[::1]"].includes(hostname);
    const secure = parsed.protocol === "https:" || localHttp;
    const rpMatches =
      hostname === rpId ||
      (!isIpAddress(rpId) && hostname.endsWith(`.${rpId}`));
    return parsed.origin === value && secure && rpMatches;
  } catch {
    return false;
  }
}

function isIpAddress(value: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(value) || value.includes(":");
}

function requireCeremony(
  payload: Readonly<Record<string, unknown>>,
  ceremony: string
): void {
  if (payload["ceremony"] !== ceremony) {
    throw new AuthError("challenge_mismatch");
  }
}

function payloadString(
  payload: Readonly<Record<string, unknown>>,
  field: string
): string {
  const value = payload[field];
  if (typeof value !== "string") throw new AuthError("challenge_mismatch");
  return value;
}

function optionalPayloadString(
  payload: Readonly<Record<string, unknown>>,
  field: string
): string | undefined {
  const value = payload[field];
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new AuthError("challenge_mismatch");
  return value;
}
