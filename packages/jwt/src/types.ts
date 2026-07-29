export type JwtAlgorithm =
  | "ES256"
  | "ES384"
  | "ES512"
  | "HS256"
  | "HS384"
  | "HS512"
  | "PS256"
  | "PS384"
  | "PS512"
  | "RS256"
  | "RS384"
  | "RS512";

export interface JwtHeader {
  readonly alg: string;
  readonly kid?: string;
  readonly typ?: string;
  readonly [key: string]: unknown;
}

export interface JwtClaims {
  readonly aud?: string | readonly string[];
  readonly exp?: number;
  readonly iat?: number;
  readonly iss?: string;
  readonly jti?: string;
  readonly nbf?: number;
  readonly sub?: string;
  readonly [key: string]: unknown;
}

export interface ParsedJwt {
  readonly header: JwtHeader;
  readonly claims: JwtClaims;
  readonly signature: Uint8Array;
  readonly signingInput: Uint8Array;
}

export type JwtKeyResolver = (
  header: JwtHeader
) => CryptoKey | Promise<CryptoKey>;

export interface VerifyJwtOptions {
  readonly algorithms: readonly JwtAlgorithm[];
  readonly key: CryptoKey | JwtKeyResolver;
  readonly audience?: string | readonly string[];
  readonly issuer?: string | readonly string[];
  readonly subject?: string;
  readonly clock?: () => Date;
  readonly clockToleranceSeconds?: number;
  readonly maxTokenAgeSeconds?: number;
}

export interface SignJwtOptions {
  readonly algorithm: JwtAlgorithm;
  readonly key: CryptoKey;
  readonly header?: Readonly<Record<string, unknown>>;
}

export type JwtErrorCode =
  | "claim_validation_failed"
  | "disallowed_algorithm"
  | "invalid_key"
  | "invalid_signature"
  | "malformed_token";
