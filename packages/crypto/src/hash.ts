export type Sha2Algorithm = "SHA-256" | "SHA-384" | "SHA-512";
export type HmacAlgorithm = "SHA-1" | Sha2Algorithm;

export async function sha2(
  algorithm: Sha2Algorithm,
  data: Uint8Array
): Promise<Uint8Array> {
  const digest = await requireSubtle().digest(algorithm, toArrayBuffer(data));
  return new Uint8Array(digest);
}

export function sha256(data: Uint8Array): Promise<Uint8Array> {
  return sha2("SHA-256", data);
}

export function sha384(data: Uint8Array): Promise<Uint8Array> {
  return sha2("SHA-384", data);
}

export function sha512(data: Uint8Array): Promise<Uint8Array> {
  return sha2("SHA-512", data);
}

export async function hmac(
  algorithm: HmacAlgorithm,
  key: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  const subtle = requireSubtle();
  const cryptoKey = await subtle.importKey(
    "raw",
    toArrayBuffer(key),
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"]
  );
  return new Uint8Array(
    await subtle.sign("HMAC", cryptoKey, toArrayBuffer(data))
  );
}

export function constantTimeEqual(
  left: Uint8Array,
  right: Uint8Array
): boolean {
  const length = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < length; index += 1) {
    difference |=
      (left[index % Math.max(1, left.length)] ?? 0) ^
      (right[index % Math.max(1, right.length)] ?? 0);
  }
  return difference === 0;
}

export function requireSubtle(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto is unavailable.");
  }
  return globalThis.crypto.subtle;
}

export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}
