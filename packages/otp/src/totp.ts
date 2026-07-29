import {
  constantTimeEqual,
  type HmacAlgorithm,
} from "@ngriffin_uk/auth-crypto";

import { generateHotp } from "./hotp.js";

const textEncoder = new TextEncoder();

export interface TotpOptions {
  readonly algorithm?: HmacAlgorithm;
  readonly digits?: number;
  readonly periodSeconds?: number;
}

export function getTotpStep(
  now: Date,
  periodSeconds = 30
): bigint {
  if (!Number.isSafeInteger(periodSeconds) || periodSeconds < 1) {
    throw new TypeError("TOTP period must be a positive integer.");
  }
  return BigInt(Math.floor(now.getTime() / 1_000 / periodSeconds));
}

export function generateTotp(
  secret: Uint8Array,
  now = new Date(),
  options: TotpOptions = {}
): Promise<string> {
  return generateHotp(
    secret,
    getTotpStep(now, options.periodSeconds),
    options
  );
}

export async function verifyTotp(
  code: string,
  secret: Uint8Array,
  now = new Date(),
  options: TotpOptions & {
    readonly window?: number;
    readonly afterStep?: bigint;
  } = {}
): Promise<{ readonly valid: boolean; readonly step?: bigint }> {
  const window = options.window ?? 1;
  if (!Number.isSafeInteger(window) || window < 0 || window > 10) {
    throw new TypeError("TOTP window must be between 0 and 10.");
  }
  const current = getTotpStep(now, options.periodSeconds);
  for (let offset = -window; offset <= window; offset += 1) {
    const step = current + BigInt(offset);
    if (step < 0n || (options.afterStep !== undefined && step <= options.afterStep)) {
      continue;
    }
    const expected = await generateHotp(secret, step, options);
    if (
      constantTimeEqual(textEncoder.encode(code), textEncoder.encode(expected))
    ) {
      return { valid: true, step };
    }
  }
  return { valid: false };
}
