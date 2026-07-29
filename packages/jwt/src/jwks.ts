import { importJwk, isJwtAlgorithm } from "./algorithm.js";
import { JwtError } from "./error.js";
import type { JwtHeader, JwtKeyResolver } from "./types.js";

export interface JwtJsonWebKey extends JsonWebKey {
  readonly alg?: string;
  readonly kid?: string;
  readonly use?: string;
}

export interface JsonWebKeySet {
  readonly keys: readonly JwtJsonWebKey[];
}

export function createJwksResolver(jwks: JsonWebKeySet): JwtKeyResolver {
  const cache = new Map<string, Promise<CryptoKey>>();
  return (header) => {
    const cacheKey = `${header.alg}:${header.kid ?? ""}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;
    const imported = resolveJwk(jwks, header);
    cache.set(cacheKey, imported);
    return imported;
  };
}

async function resolveJwk(
  jwks: JsonWebKeySet,
  header: JwtHeader
): Promise<CryptoKey> {
  if (!isJwtAlgorithm(header.alg)) {
    throw new JwtError("disallowed_algorithm", "JWT algorithm is not allowed.");
  }
  const candidates = jwks.keys.filter(
    (key) =>
      (!header.kid || key.kid === header.kid) &&
      (!key.alg || key.alg === header.alg) &&
      (!key.use || key.use === "sig")
  );
  if (candidates.length !== 1) {
    throw new JwtError(
      "invalid_key",
      candidates.length === 0
        ? "No matching JWK was found."
        : "JWT key identifier is ambiguous."
    );
  }
  const key = candidates[0];
  if (!key) {
    throw new JwtError("invalid_key", "No matching JWK was found.");
  }
  try {
    return await importJwk(key, header.alg);
  } catch (cause) {
    throw new JwtError("invalid_key", "JWK could not be imported.", { cause });
  }
}
