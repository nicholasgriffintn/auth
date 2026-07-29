import {
  decodeBase64Url,
  encodeBase64Url,
} from "@ngriffin_uk/auth-encoding";

import { encodeJson, isJwtAlgorithm, sign, verify } from "./algorithm.js";
import { JwtError } from "./error.js";
import type {
  JwtClaims,
  JwtHeader,
  ParsedJwt,
  SignJwtOptions,
  VerifyJwtOptions,
} from "./types.js";

const textDecoder = new TextDecoder("utf-8", { fatal: true });
const textEncoder = new TextEncoder();
const MAX_JWT_LENGTH = 131_072;

export async function signJwt(
  claims: JwtClaims,
  options: SignJwtOptions
): Promise<string> {
  validateSupportedHeader(options.header);
  const header = {
    typ: "JWT",
    ...options.header,
    alg: options.algorithm,
  };
  const encodedHeader = encodeBase64Url(encodeJson(header));
  const encodedClaims = encodeBase64Url(encodeJson(claims));
  const signingInput = textEncoder.encode(`${encodedHeader}.${encodedClaims}`);
  const signature = await sign(options.algorithm, options.key, signingInput);
  return `${encodedHeader}.${encodedClaims}.${encodeBase64Url(signature)}`;
}

export function parseJwt(token: string): ParsedJwt {
  if (
    typeof token !== "string" ||
    token.length === 0 ||
    token.length > MAX_JWT_LENGTH
  ) {
    throw new JwtError("malformed_token", "JWT size is invalid.");
  }
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new JwtError("malformed_token", "JWT must contain three segments.");
  }
  const [encodedHeader, encodedClaims, encodedSignature] = parts;
  if (
    encodedHeader === undefined ||
    encodedClaims === undefined ||
    encodedSignature === undefined
  ) {
    throw new JwtError("malformed_token", "JWT segments are missing.");
  }

  try {
    const headerValue = JSON.parse(
      textDecoder.decode(decodeBase64Url(encodedHeader))
    );
    const claimsValue = JSON.parse(
      textDecoder.decode(decodeBase64Url(encodedClaims))
    );
    if (!isObject(headerValue) || typeof headerValue.alg !== "string") {
      throw new TypeError("Invalid JWT header.");
    }
    if (!isObject(claimsValue)) {
      throw new TypeError("Invalid JWT claims.");
    }
    const header: JwtHeader = {
      ...headerValue,
      alg: headerValue.alg,
    };
    return {
      header,
      claims: claimsValue,
      signature: decodeBase64Url(encodedSignature),
      signingInput: textEncoder.encode(`${encodedHeader}.${encodedClaims}`),
    };
  } catch (cause) {
    if (cause instanceof JwtError) throw cause;
    throw new JwtError("malformed_token", "JWT could not be decoded.", {
      cause,
    });
  }
}

export async function verifyJwt(
  token: string,
  options: VerifyJwtOptions
): Promise<JwtClaims> {
  const parsed = parseJwt(token);
  if (
    !isJwtAlgorithm(parsed.header.alg) ||
    !options.algorithms.includes(parsed.header.alg)
  ) {
    throw new JwtError(
      "disallowed_algorithm",
      "JWT algorithm is not allowed."
    );
  }
  validateSupportedHeader(parsed.header);

  let key: CryptoKey;
  try {
    key =
      typeof options.key === "function"
        ? await options.key(parsed.header)
        : options.key;
  } catch (cause) {
    throw new JwtError("invalid_key", "JWT verification key is unavailable.", {
      cause,
    });
  }

  if (
    !(await verify(
      parsed.header.alg,
      key,
      parsed.signature,
      parsed.signingInput
    ))
  ) {
    throw new JwtError("invalid_signature", "JWT signature is invalid.");
  }

  validateClaims(parsed.claims, options);
  return parsed.claims;
}

function validateSupportedHeader(
  header: Readonly<Record<string, unknown>> | undefined
): void {
  if (
    header?.["crit"] !== undefined ||
    header?.["b64"] !== undefined
  ) {
    throw new JwtError(
      "malformed_token",
      "JWT uses unsupported critical header parameters."
    );
  }
}

function validateClaims(
  claims: JwtClaims,
  options: VerifyJwtOptions
): void {
  const clockValue = options.clock?.() ?? new Date();
  const now =
    (clockValue instanceof Date ? clockValue.getTime() : Number.NaN) /
    1_000;
  const tolerance = options.clockToleranceSeconds ?? 0;
  if (
    !Number.isFinite(now) ||
    !Number.isFinite(tolerance) ||
    tolerance < 0
  ) {
    throw new JwtError(
      "claim_validation_failed",
      "JWT clock configuration is invalid."
    );
  }
  if (
    options.maxTokenAgeSeconds !== undefined &&
    (!Number.isFinite(options.maxTokenAgeSeconds) ||
      options.maxTokenAgeSeconds < 0)
  ) {
    throw new JwtError(
      "claim_validation_failed",
      "Maximum JWT age is invalid."
    );
  }

  validateNumericClaim(claims.exp, "exp");
  validateNumericClaim(claims.nbf, "nbf");
  validateNumericClaim(claims.iat, "iat");
  if (claims.exp !== undefined && now - tolerance >= claims.exp) {
    throw claimError("JWT has expired.");
  }
  if (claims.nbf !== undefined && now + tolerance < claims.nbf) {
    throw claimError("JWT is not active yet.");
  }
  if (claims.iat !== undefined && now + tolerance < claims.iat) {
    throw claimError("JWT was issued in the future.");
  }
  if (
    options.maxTokenAgeSeconds !== undefined &&
    (claims.iat === undefined ||
      now - claims.iat - tolerance > options.maxTokenAgeSeconds)
  ) {
    throw claimError("JWT is older than the allowed token age.");
  }
  if (
    options.issuer !== undefined &&
    (typeof claims.iss !== "string" ||
      !toArray(options.issuer).includes(claims.iss))
  ) {
    throw claimError("JWT issuer is invalid.");
  }
  if (
    options.audience !== undefined &&
    !hasAudience(claims.aud, toArray(options.audience))
  ) {
    throw claimError("JWT audience is invalid.");
  }
  if (options.subject !== undefined && claims.sub !== options.subject) {
    throw claimError("JWT subject is invalid.");
  }
}

function validateNumericClaim(value: unknown, name: string): void {
  if (value !== undefined && (typeof value !== "number" || !Number.isFinite(value))) {
    throw claimError(`JWT ${name} claim is invalid.`);
  }
}

function hasAudience(
  claim: JwtClaims["aud"],
  expected: readonly string[]
): boolean {
  if (typeof claim === "string") return expected.includes(claim);
  if (Array.isArray(claim)) {
    return claim.some(
      (value) => typeof value === "string" && expected.includes(value)
    );
  }
  return false;
}

function toArray(value: string | readonly string[]): readonly string[] {
  return typeof value === "string" ? [value] : value;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function claimError(message: string): JwtError {
  return new JwtError("claim_validation_failed", message);
}
