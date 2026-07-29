import {
  AuthError,
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
  const user = await context.users.findById(input.userId);
  if (!user) throw new AuthError("invalid_input");
  const userIdBytes = textEncoder.encode(input.userId);
  if (userIdBytes.length === 0 || userIdBytes.length > 64) {
    throw new AuthError(
      "invalid_input",
      "The WebAuthn user ID must be between 1 and 64 bytes."
    );
  }
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
  try {
    parsed = await validateRegistration(response, {
      challenge: token,
      rpId: config.rpId,
      origins: config.origins,
      ...(config.requireUserVerification === undefined
        ? {}
        : { requireUserVerification: config.requireUserVerification }),
    });
  } catch (cause) {
    throw new AuthError("invalid_credentials", "The passkey registration is invalid.", {
      cause,
    });
  }
  await config.store.saveCredential({
    id: encodeBase64Url(parsed.credentialId!),
    userId,
    publicKeyJwk: parsed.credentialPublicKey!,
    algorithm: parsed.algorithm!,
    signCount: parsed.signCount,
    ...(response.transports ? { transports: response.transports } : {}),
    backupEligible: parsed.backupEligible,
    backedUp: parsed.backedUp,
    createdAt: context.now(),
    updatedAt: context.now(),
  });
  return authenticated(context, userId);
}

async function startAuthentication<User extends AuthUser>(
  context: AuthPluginContext<User>,
  config: WebAuthnPluginConfig,
  userId?: string
): Promise<AuthFlowResult<User>> {
  if (userId && !(await context.users.findById(userId))) {
    throw new AuthError("invalid_input");
  }
  const credentials = userId
    ? await config.store.listCredentials(userId)
    : [];
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
    ...(credentials.length > 0
      ? { allowCredentialIds: credentials.map((credential) => credential.id) }
      : {}),
  });
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
    config.origins.length === 0 ||
    config.origins.some((origin) => !isValidOrigin(origin, config.rpId))
  ) {
    throw new TypeError("WebAuthn RP ID and origins must be valid.");
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
    if (encoded.length === 0 || encoded.length > 16_384) return false;
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
