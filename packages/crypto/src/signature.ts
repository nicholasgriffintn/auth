import {
  requireSubtle,
  toArrayBuffer,
  type HmacAlgorithm,
  type Sha2Algorithm,
} from "./hash.js";

export async function signHmac(
  algorithm: HmacAlgorithm,
  key: CryptoKey,
  data: Uint8Array
): Promise<Uint8Array> {
  return new Uint8Array(
    await requireSubtle().sign("HMAC", key, toArrayBuffer(data))
  );
}

export async function verifyHmac(
  algorithm: HmacAlgorithm,
  key: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  return requireSubtle().verify(
    { name: "HMAC", hash: algorithm },
    key,
    toArrayBuffer(signature),
    toArrayBuffer(data)
  );
}

export async function signRsaPkcs1(
  key: CryptoKey,
  data: Uint8Array
): Promise<Uint8Array> {
  return new Uint8Array(
    await requireSubtle().sign(
      "RSASSA-PKCS1-v1_5",
      key,
      toArrayBuffer(data)
    )
  );
}

export function verifyRsaPkcs1(
  key: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  return requireSubtle().verify(
    "RSASSA-PKCS1-v1_5",
    key,
    toArrayBuffer(signature),
    toArrayBuffer(data)
  );
}

export async function signRsaPss(
  key: CryptoKey,
  data: Uint8Array,
  saltLength: number
): Promise<Uint8Array> {
  return new Uint8Array(
    await requireSubtle().sign(
      { name: "RSA-PSS", saltLength },
      key,
      toArrayBuffer(data)
    )
  );
}

export function verifyRsaPss(
  key: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array,
  saltLength: number
): Promise<boolean> {
  return requireSubtle().verify(
    { name: "RSA-PSS", saltLength },
    key,
    toArrayBuffer(signature),
    toArrayBuffer(data)
  );
}

export async function signEcdsa(
  key: CryptoKey,
  data: Uint8Array,
  hash: Sha2Algorithm
): Promise<Uint8Array> {
  return new Uint8Array(
    await requireSubtle().sign(
      { name: "ECDSA", hash },
      key,
      toArrayBuffer(data)
    )
  );
}

export function verifyEcdsa(
  key: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array,
  hash: Sha2Algorithm
): Promise<boolean> {
  return requireSubtle().verify(
    { name: "ECDSA", hash },
    key,
    toArrayBuffer(signature),
    toArrayBuffer(data)
  );
}
