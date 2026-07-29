import { AuthError } from "./errors.js";

const textEncoder = new TextEncoder();

export function normaliseEmail(email: string): string {
  return email.trim().toLocaleLowerCase("en-US");
}

export function getSecureRandomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 1) {
    throw new AuthError("invalid_input", "Random byte length must be positive.");
  }
  if (!globalThis.crypto?.getRandomValues) {
    throw new AuthError("insecure_runtime");
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export async function hashSecret(secret: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new AuthError("insecure_runtime");
  }
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    textEncoder.encode(secret)
  );
  return encodeBase64Url(new Uint8Array(digest));
}

export function requireValidDate(value: Date, field: string): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new AuthError("invalid_input", `${field} must be a valid date.`);
  }
  return value;
}

export function expirationDate(
  createdAt: Date,
  ttlMs: number,
  field: string
): Date {
  const expiresAt = new Date(createdAt.getTime() + ttlMs);
  return requireValidDate(expiresAt, field);
}
