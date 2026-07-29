import type { HmacAlgorithm } from "@ngriffin_uk/auth-crypto";
import { encodeBase32 } from "@ngriffin_uk/auth-encoding";

import { validateOtpParameters } from "./validation.js";

export interface TotpUriOptions {
  readonly issuer: string;
  readonly accountName: string;
  readonly secret: Uint8Array;
  readonly algorithm?: HmacAlgorithm;
  readonly digits?: number;
  readonly periodSeconds?: number;
}

export function createTotpUri(options: TotpUriOptions): URL {
  if (
    typeof options.issuer !== "string" ||
    !options.issuer.trim() ||
    options.issuer.length > 128 ||
    typeof options.accountName !== "string" ||
    !options.accountName.trim() ||
    options.accountName.length > 320
  ) {
    throw new TypeError("OTP issuer or account name is invalid.");
  }
  validateOtpParameters(
    options.secret,
    options.digits ?? 6,
    options.algorithm ?? "SHA-1"
  );
  if (
    options.periodSeconds !== undefined &&
    (!Number.isSafeInteger(options.periodSeconds) ||
      options.periodSeconds < 1)
  ) {
    throw new TypeError("TOTP period must be a positive integer.");
  }
  const label = `${options.issuer}:${options.accountName}`;
  const url = new URL(`otpauth://totp/${encodeURIComponent(label)}`);
  url.searchParams.set("secret", encodeBase32(options.secret));
  url.searchParams.set("issuer", options.issuer);
  url.searchParams.set(
    "algorithm",
    (options.algorithm ?? "SHA-1").replace("-", "")
  );
  url.searchParams.set("digits", String(options.digits ?? 6));
  url.searchParams.set("period", String(options.periodSeconds ?? 30));
  return url;
}
