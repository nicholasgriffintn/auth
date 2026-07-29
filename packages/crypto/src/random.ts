import { encodeBase64Url } from "@ngriffin_uk/auth-encoding";

export function randomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 1) {
    throw new TypeError("Random byte length must be a positive integer.");
  }
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("Secure random values are unavailable.");
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

export function randomString(byteLength = 32): string {
  return encodeBase64Url(randomBytes(byteLength));
}
