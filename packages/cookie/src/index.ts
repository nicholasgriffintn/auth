const COOKIE_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const INVALID_ATTRIBUTE_PATTERN = /[\u0000-\u001F\u007F;]/u;

export interface CookieAttributes {
  readonly domain?: string;
  readonly expires?: Date;
  readonly httpOnly?: boolean;
  readonly maxAge?: number;
  readonly partitioned?: boolean;
  readonly path?: string;
  readonly priority?: "low" | "medium" | "high";
  readonly sameSite?: "lax" | "strict" | "none";
  readonly secure?: boolean;
}

export function serializeCookie(
  name: string,
  value: string,
  attributes: CookieAttributes = {}
): string {
  validateCookie(name, attributes);
  const parts = [`${name}=${encodeURIComponent(value)}`];

  if (attributes.domain) parts.push(`Domain=${attributes.domain}`);
  if (attributes.expires) parts.push(`Expires=${attributes.expires.toUTCString()}`);
  if (attributes.httpOnly) parts.push("HttpOnly");
  if (attributes.maxAge !== undefined) {
    if (!Number.isSafeInteger(attributes.maxAge)) {
      throw new TypeError("Cookie Max-Age must be an integer.");
    }
    parts.push(`Max-Age=${attributes.maxAge}`);
  }
  if (attributes.path) parts.push(`Path=${attributes.path}`);
  if (attributes.priority) {
    parts.push(
      `Priority=${attributes.priority[0]?.toUpperCase()}${attributes.priority.slice(1)}`
    );
  }
  if (attributes.sameSite) {
    parts.push(
      `SameSite=${attributes.sameSite[0]?.toUpperCase()}${attributes.sameSite.slice(1)}`
    );
  }
  if (attributes.secure) parts.push("Secure");
  if (attributes.partitioned) parts.push("Partitioned");

  return parts.join("; ");
}

export function parseCookies(header: string): ReadonlyMap<string, string> {
  const cookies = new Map<string, string>();
  for (const item of header.split(";")) {
    const separator = item.indexOf("=");
    if (separator < 1) continue;
    const name = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();
    if (!COOKIE_NAME_PATTERN.test(name)) continue;
    try {
      cookies.set(name, decodeURIComponent(value));
    } catch {
      // Ignore malformed cookie pairs while preserving valid neighbours.
    }
  }
  return cookies;
}

export function serializeSessionCookie(
  name: string,
  value: string,
  options: Omit<
    CookieAttributes,
    "httpOnly" | "sameSite" | "secure"
  > & {
    readonly httpOnly?: true;
    readonly sameSite?: "lax" | "strict";
    readonly secure?: true;
  } = {}
): string {
  return serializeCookie(name, value, {
    path: "/",
    ...options,
    httpOnly: true,
    sameSite: options.sameSite ?? "lax",
    secure: true,
  });
}

export function serializeExpiredCookie(
  name: string,
  attributes: CookieAttributes = {}
): string {
  return serializeCookie(name, "", {
    path: "/",
    ...attributes,
    expires: new Date(0),
    maxAge: 0,
  });
}

function validateCookie(name: string, attributes: CookieAttributes): void {
  if (!COOKIE_NAME_PATTERN.test(name)) {
    throw new TypeError("Invalid cookie name.");
  }
  for (const [label, value] of [
    ["Domain", attributes.domain],
    ["Path", attributes.path],
  ] as const) {
    if (value && INVALID_ATTRIBUTE_PATTERN.test(value)) {
      throw new TypeError(`Invalid cookie ${label}.`);
    }
  }
  if (attributes.sameSite === "none" && !attributes.secure) {
    throw new TypeError("SameSite=None cookies must be Secure.");
  }
  if (attributes.partitioned && !attributes.secure) {
    throw new TypeError("Partitioned cookies must be Secure.");
  }
  if (name.startsWith("__Host-")) {
    if (!attributes.secure || attributes.path !== "/" || attributes.domain) {
      throw new TypeError(
        "__Host- cookies require Secure, Path=/, and no Domain."
      );
    }
  }
}
