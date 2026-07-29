const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const LOOKUP = new Map(
  [...ALPHABET].map((character, index) => [character, index])
);

export function encodeBase32(bytes: Uint8Array, padding = false): string {
  let output = "";
  let buffer = 0;
  let bits = 0;

  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += ALPHABET[(buffer >>> bits) & 31];
    }
  }
  if (bits > 0) {
    output += ALPHABET[(buffer << (5 - bits)) & 31];
  }
  return padding ? output.padEnd(Math.ceil(output.length / 8) * 8, "=") : output;
}

export function decodeBase32(value: string): Uint8Array {
  const unpadded = value.toUpperCase().replace(/=+$/u, "");
  const paddingLength = value.length - unpadded.length;
  if (paddingLength > 6 || unpadded.includes("=")) {
    throw new TypeError("Invalid base32 string.");
  }

  const output: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of unpadded) {
    const decoded = LOOKUP.get(character);
    if (decoded === undefined) {
      throw new TypeError("Invalid base32 string.");
    }
    buffer = (buffer << 5) | decoded;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((buffer >>> bits) & 255);
    }
  }

  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) {
    throw new TypeError("Invalid base32 trailing bits.");
  }
  return Uint8Array.from(output);
}
