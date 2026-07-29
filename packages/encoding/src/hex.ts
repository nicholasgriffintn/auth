const HEX_PATTERN = /^[0-9a-f]*$/iu;

export function encodeHex(bytes: Uint8Array): string {
  let output = "";
  for (const byte of bytes) {
    output += byte.toString(16).padStart(2, "0");
  }
  return output;
}

export function decodeHex(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !HEX_PATTERN.test(value)) {
    throw new TypeError("Invalid hexadecimal string.");
  }
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < value.length; index += 2) {
    output[index / 2] = Number.parseInt(value.slice(index, index + 2), 16);
  }
  return output;
}
