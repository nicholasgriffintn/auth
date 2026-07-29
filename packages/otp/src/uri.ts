import type { HmacAlgorithm } from "@ngriffin_uk/auth-crypto";
import { encodeBase32 } from "@ngriffin_uk/auth-encoding";

export interface TotpUriOptions {
  readonly issuer: string;
  readonly accountName: string;
  readonly secret: Uint8Array;
  readonly algorithm?: HmacAlgorithm;
  readonly digits?: number;
  readonly periodSeconds?: number;
}

export function createTotpUri(options: TotpUriOptions): URL {
  if (!options.issuer.trim() || !options.accountName.trim()) {
    throw new TypeError("OTP issuer and account name are required.");
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
