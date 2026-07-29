import {
  readResponseText,
  requestWithTimeout,
} from "@ngriffin_uk/auth-request";

import { JwtError } from "./error.js";
import { createJwksResolver, type JsonWebKeySet } from "./jwks.js";
import type { JwtHeader, JwtKeyResolver } from "./types.js";

const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1_000;
const DEFAULT_MINIMUM_REFRESH_INTERVAL_MS = 60 * 1_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;

export interface RemoteJwksOptions {
  readonly url: string;
  readonly fetch?: typeof globalThis.fetch;
  readonly cacheTtlMs?: number;
  readonly minimumRefreshIntervalMs?: number;
  readonly maxResponseBytes?: number;
  readonly timeoutMs?: number;
  readonly clock?: () => Date;
}

interface CachedJwks {
  readonly expiresAt: number;
  readonly resolver: JwtKeyResolver;
}

export function createRemoteJwksResolver(
  options: RemoteJwksOptions
): JwtKeyResolver {
  const url = validateJwksUrl(options.url);
  const request = options.fetch ?? globalThis.fetch;
  if (!request) {
    throw new JwtError("invalid_key", "Fetch is unavailable.");
  }
  const clock = options.clock ?? (() => new Date());
  const cacheTtlMs = positiveInteger(
    options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS,
    "JWKS cache lifetime"
  );
  const minimumRefreshIntervalMs = positiveInteger(
    options.minimumRefreshIntervalMs ?? DEFAULT_MINIMUM_REFRESH_INTERVAL_MS,
    "JWKS refresh interval"
  );
  const maxResponseBytes = positiveInteger(
    options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    "JWKS response size"
  );
  const timeoutMs = positiveInteger(
    options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    "JWKS request timeout"
  );

  let cached: CachedJwks | null = null;
  let inFlight: Promise<CachedJwks> | null = null;
  let lastRefreshAt = Number.NEGATIVE_INFINITY;

  async function load(force: boolean): Promise<CachedJwks> {
    const now = clock().getTime();
    if (!force && cached && cached.expiresAt > now) {
      return cached;
    }
    if (inFlight) {
      return inFlight;
    }
    inFlight = fetchJwks(request, url, maxResponseBytes, timeoutMs).then(
      ({ jwks, responseTtlMs }) => {
        const loadedAt = clock().getTime();
        lastRefreshAt = loadedAt;
        const result = {
          expiresAt: loadedAt + Math.min(cacheTtlMs, responseTtlMs ?? cacheTtlMs),
          resolver: createJwksResolver(jwks),
        };
        cached = result;
        return result;
      }
    );
    try {
      return await inFlight;
    } finally {
      inFlight = null;
    }
  }

  return async (header: JwtHeader) => {
    const current = await load(false);
    try {
      return await current.resolver(header);
    } catch (cause) {
      const canRefresh =
        cause instanceof JwtError &&
        cause.code === "invalid_key" &&
        clock().getTime() - lastRefreshAt >= minimumRefreshIntervalMs;
      if (!canRefresh) {
        throw cause;
      }
      const refreshed = await load(true);
      return refreshed.resolver(header);
    }
  };
}

async function fetchJwks(
  request: typeof globalThis.fetch,
  url: URL,
  maxResponseBytes: number,
  timeoutMs: number
): Promise<{ jwks: JsonWebKeySet; responseTtlMs?: number }> {
  let response: Response;
  try {
    response = await requestWithTimeout(
      request,
      url,
      {
        headers: { Accept: "application/json" },
        redirect: "error",
      },
      timeoutMs
    );
  } catch (cause) {
    throw new JwtError("invalid_key", "JWKS endpoint is unavailable.", {
      cause,
    });
  }
  if (!response.ok) {
    throw new JwtError("invalid_key", "JWKS endpoint rejected the request.");
  }

  let text: string;
  try {
    text = await readResponseText(response, maxResponseBytes);
  } catch {
    throw new JwtError("invalid_key", "JWKS response is too large.");
  }

  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (cause) {
    throw new JwtError("invalid_key", "JWKS response is invalid.", { cause });
  }
  if (!isJwks(value)) {
    throw new JwtError("invalid_key", "JWKS response is invalid.");
  }
  const responseTtlMs = parseMaxAge(response.headers.get("Cache-Control"));
  return {
    jwks: value,
    ...(responseTtlMs === undefined ? {} : { responseTtlMs }),
  };
}

function validateJwksUrl(value: string): URL {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash
  ) {
    throw new JwtError("invalid_key", "JWKS URL must be a secure HTTPS URL.");
  }
  return url;
}

function isJwks(value: unknown): value is JsonWebKeySet {
  if (!isObject(value) || !Array.isArray(value.keys) || value.keys.length === 0) {
    return false;
  }
  return value.keys.every(
    (key) =>
      isObject(key) &&
      typeof key.kty === "string" &&
      (key.kid === undefined || typeof key.kid === "string") &&
      (key.alg === undefined || typeof key.alg === "string") &&
      (key.use === undefined || typeof key.use === "string")
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseMaxAge(cacheControl: string | null): number | undefined {
  if (!cacheControl) return undefined;
  const match = /(?:^|,)\s*max-age=(\d+)(?:,|$)/iu.exec(cacheControl);
  if (!match?.[1]) return undefined;
  const seconds = Number(match[1]);
  return Number.isSafeInteger(seconds) ? seconds * 1_000 : undefined;
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive integer.`);
  }
  return value;
}
