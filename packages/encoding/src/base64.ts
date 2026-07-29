const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/u;

export function encodeBase64(bytes: Uint8Array): string {
  return btoa(bytesToBinary(bytes));
}

export function decodeBase64(value: string): Uint8Array {
  if (!BASE64_PATTERN.test(value)) {
    throw new TypeError("Invalid base64 string.");
  }
  return binaryToBytes(atob(value));
}

export function encodeBase64Url(
  bytes: Uint8Array,
  padding = false
): string {
  const encoded = encodeBase64(bytes)
    .replaceAll("+", "-")
    .replaceAll("/", "_");
  return padding ? encoded : encoded.replace(/=+$/u, "");
}

export function decodeBase64Url(value: string): Uint8Array {
  const unpadded = value.replace(/=+$/u, "");
  if (
    !BASE64URL_PATTERN.test(unpadded) ||
    value.length - unpadded.length > 2 ||
    unpadded.length % 4 === 1
  ) {
    throw new TypeError("Invalid base64url string.");
  }
  const normalised = unpadded
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(unpadded.length / 4) * 4, "=");
  return decodeBase64(normalised);
}

function bytesToBinary(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return binary;
}

function binaryToBytes(binary: string): Uint8Array {
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    output[index] = binary.charCodeAt(index);
  }
  return output;
}
