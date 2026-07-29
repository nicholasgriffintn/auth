const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function verifyRequestOrigin(
  origin: string,
  allowedOrigins: readonly string[]
): boolean {
  const candidate = parseOrigin(origin);
  if (!candidate) return false;

  return allowedOrigins.some((allowed) => {
    const parsed = parseAllowedOrigin(allowed);
    return parsed ? candidate.origin === parsed.origin : false;
  });
}

export function verifyRequestCsrf(
  request: Pick<Request, "headers" | "method">,
  allowedOrigins: readonly string[]
): boolean {
  if (SAFE_METHODS.has(request.method.toUpperCase())) {
    return true;
  }

  const fetchSite = request.headers.get("Sec-Fetch-Site");
  if (fetchSite === "cross-site") {
    return false;
  }

  const origin = request.headers.get("Origin");
  return origin ? verifyRequestOrigin(origin, allowedOrigins) : false;
}

export function assertRequestCsrf(
  request: Pick<Request, "headers" | "method">,
  allowedOrigins: readonly string[]
): void {
  if (!verifyRequestCsrf(request, allowedOrigins)) {
    throw new TypeError("Request origin is not allowed.");
  }
}

export async function requestWithTimeout(
  request: typeof globalThis.fetch,
  input: RequestInfo | URL,
  init: RequestInit,
  timeoutMs: number
): Promise<Response> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("Request timeout must be a positive integer.");
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await request(input, {
      ...init,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

export async function readResponseText(
  response: Response,
  maxBytes: number
): Promise<string> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new TypeError("Response size limit must be a positive integer.");
  }
  const declaredLength = Number(response.headers.get("Content-Length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new TypeError("Response exceeds the configured size limit.");
  }
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      length += result.value.byteLength;
      if (length > maxBytes) {
        await reader.cancel();
        throw new TypeError("Response exceeds the configured size limit.");
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

function parseOrigin(value: string): URL | null {
  try {
    const url = new URL(value);
    if (
      (url.protocol !== "https:" && url.protocol !== "http:") ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) {
      return null;
    }
    return url;
  } catch {
    return null;
  }
}

function parseAllowedOrigin(value: string): URL | null {
  if (value.includes("://")) {
    return parseOrigin(value);
  }
  return parseOrigin(`https://${value}`);
}
