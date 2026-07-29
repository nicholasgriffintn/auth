import type { HmacAlgorithm } from "@ngriffin_uk/auth-crypto";

const OTP_ALGORITHMS = new Set<HmacAlgorithm>([
  "SHA-1",
  "SHA-256",
  "SHA-384",
  "SHA-512",
]);

export function validateOtpParameters(
  secret: Uint8Array,
  digits: number,
  algorithm: HmacAlgorithm
): void {
  if (!(secret instanceof Uint8Array) || secret.length < 16) {
    throw new TypeError("OTP secrets must contain at least 128 bits.");
  }
  if (!Number.isSafeInteger(digits) || digits < 6 || digits > 10) {
    throw new TypeError("OTP digits must be between 6 and 10.");
  }
  if (!OTP_ALGORITHMS.has(algorithm)) {
    throw new TypeError("OTP hash algorithm is invalid.");
  }
}

export function isValidOtpCode(code: string, digits: number): boolean {
  return (
    typeof code === "string" &&
    code.length === digits &&
    /^[0-9]+$/u.test(code)
  );
}
