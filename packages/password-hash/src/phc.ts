import {
  decodeBase64,
  encodeBase64,
} from "@ngriffin_uk/auth-encoding";

export interface Argon2idRecord {
  readonly memoryCostKiB: number;
  readonly timeCost: number;
  readonly parallelism: number;
  readonly salt: Uint8Array;
  readonly hash: Uint8Array;
}

export function formatArgon2idRecord(record: Argon2idRecord): string {
  return [
    "$argon2id$v=19$m=",
    String(record.memoryCostKiB),
    ",t=",
    String(record.timeCost),
    ",p=",
    String(record.parallelism),
    "$",
    encodeUnpaddedBase64(record.salt),
    "$",
    encodeUnpaddedBase64(record.hash),
  ].join("");
}

export function parseArgon2idRecord(value: string): Argon2idRecord | null {
  if (value.length > 16_384) return null;
  const match =
    /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/u.exec(
      value
    );
  if (!match?.[1] || !match[2] || !match[3] || !match[4] || !match[5]) {
    return null;
  }
  const memoryCostKiB = Number(match[1]);
  const timeCost = Number(match[2]);
  const parallelism = Number(match[3]);
  if (
    !Number.isSafeInteger(memoryCostKiB) ||
    !Number.isSafeInteger(timeCost) ||
    !Number.isSafeInteger(parallelism)
  ) {
    return null;
  }
  try {
    return {
      memoryCostKiB,
      timeCost,
      parallelism,
      salt: decodeUnpaddedBase64(match[4]),
      hash: decodeUnpaddedBase64(match[5]),
    };
  } catch {
    return null;
  }
}

function encodeUnpaddedBase64(value: Uint8Array): string {
  return encodeBase64(value).replace(/=+$/u, "");
}

function decodeUnpaddedBase64(value: string): Uint8Array {
  return decodeBase64(
    value.padEnd(Math.ceil(value.length / 4) * 4, "=")
  );
}
