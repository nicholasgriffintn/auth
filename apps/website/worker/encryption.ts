import { isRecord } from "@ngriffin_uk/auth-core";
import {
  decodeBase64Url,
  encodeBase64Url,
} from "@ngriffin_uk/auth-encoding";

import { toArrayBuffer } from "../shared/bytes.ts";

const IV_BYTES = 12;
const KEY_BYTES = 32;
const MAX_ENCRYPTED_BYTES = 128 * 1_024;
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const textEncoder = new TextEncoder();

export interface EncryptedValue {
  readonly ciphertext: string;
  readonly iv: string;
}

export interface AuthEncryption {
  encryptBytes(value: Uint8Array, context: string): Promise<EncryptedValue>;
  decryptBytes(value: EncryptedValue, context: string): Promise<Uint8Array>;
  encryptJson(
    value: Readonly<Record<string, unknown>>,
    context: string,
  ): Promise<EncryptedValue>;
  decryptJson(
    value: EncryptedValue,
    context: string,
  ): Promise<Readonly<Record<string, unknown>>>;
}

export async function createAuthEncryption(
  encodedKey: string | undefined,
): Promise<AuthEncryption> {
  if (!encodedKey?.trim()) {
    throw new TypeError("AUTH_ENCRYPTION_KEY is not configured.");
  }
  const keyBytes = decodeBase64Url(encodedKey.trim());
  if (keyBytes.byteLength !== KEY_BYTES) {
    throw new TypeError("AUTH_ENCRYPTION_KEY must contain 32 bytes.");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(keyBytes),
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  );

  async function encryptBytes(
    value: Uint8Array,
    context: string,
  ): Promise<EncryptedValue> {
    if (value.byteLength > MAX_ENCRYPTED_BYTES) {
      throw new TypeError("Authentication data is too large.");
    }
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(iv),
        additionalData: textEncoder.encode(context),
      },
      key,
      toArrayBuffer(value),
    );
    return {
      ciphertext: encodeBase64Url(new Uint8Array(ciphertext)),
      iv: encodeBase64Url(iv),
    };
  }

  async function decryptBytes(
    value: EncryptedValue,
    context: string,
  ): Promise<Uint8Array> {
    const ciphertext = decodeBase64Url(value.ciphertext);
    const iv = decodeBase64Url(value.iv);
    if (
      iv.byteLength !== IV_BYTES ||
      ciphertext.byteLength > MAX_ENCRYPTED_BYTES + 16
    ) {
      throw new TypeError("Encrypted authentication data is invalid.");
    }
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(iv),
        additionalData: textEncoder.encode(context),
      },
      key,
      toArrayBuffer(ciphertext),
    );
    return new Uint8Array(plaintext);
  }

  return {
    encryptBytes,
    decryptBytes,
    encryptJson: (value, context) =>
      encryptBytes(textEncoder.encode(JSON.stringify(value)), context),
    async decryptJson(value, context) {
      const decoded: unknown = JSON.parse(
        textDecoder.decode(await decryptBytes(value, context)),
      );
      if (!isRecord(decoded)) {
        throw new TypeError("Encrypted authentication payload is invalid.");
      }
      return decoded;
    },
  };
}
