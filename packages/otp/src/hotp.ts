import {
  constantTimeEqual,
  hmac,
  type HmacAlgorithm,
} from "@ngriffin_uk/auth-crypto";

import {
  isValidOtpCode,
  validateOtpParameters,
} from "./validation.js";

const textEncoder = new TextEncoder();

export interface HotpOptions {
  readonly algorithm?: HmacAlgorithm;
  readonly digits?: number;
}

export async function generateHotp(
  secret: Uint8Array,
  counter: bigint,
  options: HotpOptions = {}
): Promise<string> {
  validateOptions(
    secret,
    counter,
    options.digits ?? 6,
    options.algorithm ?? "SHA-1"
  );
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setBigUint64(0, counter, false);
  const digest = await hmac(
    options.algorithm ?? "SHA-1",
    secret,
    counterBytes
  );
  const offset = (digest[digest.length - 1] ?? 0) & 15;
  const binary =
    (((digest[offset] ?? 0) & 127) << 24) |
    ((digest[offset + 1] ?? 0) << 16) |
    ((digest[offset + 2] ?? 0) << 8) |
    (digest[offset + 3] ?? 0);
  const digits = options.digits ?? 6;
  return (binary % 10 ** digits).toString().padStart(digits, "0");
}

export async function verifyHotp(
  code: string,
  secret: Uint8Array,
  counter: bigint,
  options: HotpOptions & { readonly lookAhead?: number } = {}
): Promise<{ readonly valid: boolean; readonly counter?: bigint }> {
  const lookAhead = options.lookAhead ?? 0;
  if (!Number.isSafeInteger(lookAhead) || lookAhead < 0 || lookAhead > 100) {
    throw new TypeError("HOTP look-ahead must be between 0 and 100.");
  }
  const digits = options.digits ?? 6;
  validateOptions(
    secret,
    counter,
    digits,
    options.algorithm ?? "SHA-1"
  );
  if (counter + BigInt(lookAhead) > 0xffffffffffffffffn) {
    throw new TypeError("HOTP look-ahead exceeds the 64-bit counter range.");
  }
  if (!isValidOtpCode(code, digits)) return { valid: false };
  for (let offset = 0; offset <= lookAhead; offset += 1) {
    const candidateCounter = counter + BigInt(offset);
    const expected = await generateHotp(secret, candidateCounter, options);
    if (
      constantTimeEqual(textEncoder.encode(code), textEncoder.encode(expected))
    ) {
      return { valid: true, counter: candidateCounter };
    }
  }
  return { valid: false };
}

function validateOptions(
  secret: Uint8Array,
  counter: bigint,
  digits: number,
  algorithm: HmacAlgorithm
): void {
  validateOtpParameters(secret, digits, algorithm);
  if (
    typeof counter !== "bigint" ||
    counter < 0n ||
    counter > 0xffffffffffffffffn
  ) {
    throw new TypeError("HOTP counter is outside the 64-bit range.");
  }
}
