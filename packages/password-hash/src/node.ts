import * as nodeCrypto from "node:crypto";
import { constantTimeEqual, randomBytes } from "@ngriffin_uk/auth-crypto";
import {
  decodeBase64Url,
  encodeBase64Url,
} from "@ngriffin_uk/auth-encoding";

import type { UpgradeablePasswordHasher } from "./index.js";
import {
  formatArgon2idRecord,
  parseArgon2idRecord,
} from "./phc.js";

const textEncoder = new TextEncoder();
const MAX_ARGON2_MEMORY_KIB = 256 * 1024;
const MAX_ARGON2_TIME_COST = 10;
const MAX_ARGON2_PARALLELISM = 16;
const MAX_HASH_COMPONENT_BYTES = 1024;
const MAX_HASH_RECORD_LENGTH = 16_384;
const MAX_SCRYPT_BLOCK_SIZE = 32;
const MAX_SCRYPT_PARALLELISM = 16;

export interface Argon2idOptions {
  readonly memoryCostKiB?: number;
  readonly timeCost?: number;
  readonly parallelism?: number;
  readonly outputLength?: number;
}

export function createArgon2idHasher(
  options: Argon2idOptions = {}
): UpgradeablePasswordHasher {
  if (typeof nodeCrypto.argon2 !== "function") {
    throw new TypeError("Argon2id requires Node.js 24.7 or newer.");
  }
  const memoryCost = positiveInteger(options.memoryCostKiB ?? 19 * 1024);
  const timeCost = positiveInteger(options.timeCost ?? 2);
  const parallelism = positiveInteger(options.parallelism ?? 1);
  const outputLen = positiveInteger(options.outputLength ?? 32);
  validateArgon2Parameters(memoryCost, timeCost, parallelism, outputLen);

  return {
    async hash(password) {
      validatePassword(password);
      const salt = randomBytes(16);
      const hash = await deriveArgon2id(
        password,
        salt,
        memoryCost,
        timeCost,
        parallelism,
        outputLen
      );
      return formatArgon2idRecord({
        memoryCostKiB: memoryCost,
        timeCost,
        parallelism,
        salt,
        hash,
      });
    },
    async verify(password, passwordHash) {
      return (await this.verifyAndCheck(password, passwordHash)).valid;
    },
    async verifyAndCheck(password, passwordHash) {
      validatePassword(password);
      const record = parseArgon2idRecord(passwordHash);
      if (!record || !validStoredArgon2Parameters(record)) {
        return { valid: false, needsRehash: false };
      }
      try {
        const derived = await deriveArgon2id(
          password,
          record.salt,
          record.memoryCostKiB,
          record.timeCost,
          record.parallelism,
          record.hash.length
        );
        const valid = constantTimeEqual(derived, record.hash);
        return {
          valid,
          needsRehash:
            valid &&
            (record.memoryCostKiB !== memoryCost ||
              record.timeCost !== timeCost ||
              record.parallelism !== parallelism ||
              record.hash.length !== outputLen ||
              record.salt.length !== 16),
        };
      } catch {
        return { valid: false, needsRehash: false };
      }
    },
  };
}

export interface ScryptOptions {
  readonly cost?: number;
  readonly blockSize?: number;
  readonly parallelism?: number;
  readonly saltBytes?: number;
  readonly keyBytes?: number;
  readonly maxMemoryBytes?: number;
}

export function createScryptHasher(
  options: ScryptOptions = {}
): UpgradeablePasswordHasher {
  const cost = positiveInteger(options.cost ?? 2 ** 17);
  const blockSize = positiveInteger(options.blockSize ?? 8);
  const parallelism = positiveInteger(options.parallelism ?? 1);
  const saltBytes = positiveInteger(options.saltBytes ?? 16);
  const keyBytes = positiveInteger(options.keyBytes ?? 32);
  const maxMemoryBytes = positiveInteger(
    options.maxMemoryBytes ?? Math.max(256 * 1024 * 1024, 256 * cost * blockSize)
  );
  if (
    (cost & (cost - 1)) !== 0 ||
    cost > 2 ** 20 ||
    blockSize > MAX_SCRYPT_BLOCK_SIZE ||
    parallelism > MAX_SCRYPT_PARALLELISM ||
    saltBytes > MAX_HASH_COMPONENT_BYTES ||
    keyBytes < 16 ||
    keyBytes > MAX_HASH_COMPONENT_BYTES
  ) {
    throw new TypeError("Scrypt parameters are outside the supported bounds.");
  }

  return {
    async hash(password) {
      validatePassword(password);
      const salt = randomBytes(saltBytes);
      const derived = await scrypt(
        password,
        salt,
        keyBytes,
        cost,
        blockSize,
        parallelism,
        maxMemoryBytes
      );
      return `$scrypt$ln=${Math.log2(cost)},r=${blockSize},p=${parallelism}$${encodeBase64Url(salt)}$${encodeBase64Url(derived)}`;
    },
    async verify(password, passwordHash) {
      return (await this.verifyAndCheck(password, passwordHash)).valid;
    },
    async verifyAndCheck(password, passwordHash) {
      validatePassword(password);
      const parsed = parseScryptHash(passwordHash);
      if (!parsed) {
        return { valid: false, needsRehash: false };
      }
      try {
        const derived = await scrypt(
          password,
          parsed.salt,
          parsed.hash.length,
          parsed.cost,
          parsed.blockSize,
          parsed.parallelism,
          maxMemoryBytes
        );
        const valid = constantTimeEqual(derived, parsed.hash);
        return {
          valid,
          needsRehash:
            valid &&
            (parsed.cost !== cost ||
              parsed.blockSize !== blockSize ||
              parsed.parallelism !== parallelism ||
              parsed.salt.length !== saltBytes ||
              parsed.hash.length !== keyBytes),
        };
      } catch {
        return { valid: false, needsRehash: false };
      }
    },
  };
}

function scrypt(
  password: string,
  salt: Uint8Array,
  keyBytes: number,
  cost: number,
  blockSize: number,
  parallelism: number,
  maxmem: number
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    nodeCrypto.scrypt(
      password,
      salt,
      keyBytes,
      { N: cost, r: blockSize, p: parallelism, maxmem },
      (error, derived) => {
        if (error) reject(error);
        else resolve(new Uint8Array(derived));
      }
    );
  });
}

function deriveArgon2id(
  password: string,
  salt: Uint8Array,
  memory: number,
  passes: number,
  parallelism: number,
  tagLength: number
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    nodeCrypto.argon2(
      "argon2id",
      {
        message: textEncoder.encode(password),
        nonce: salt,
        parallelism,
        tagLength,
        memory,
        passes,
      },
      (error, derived) => {
        if (error) reject(error);
        else resolve(new Uint8Array(derived));
      }
    );
  });
}

function validateArgon2Parameters(
  memory: number,
  time: number,
  parallelism: number,
  outputLength: number
): void {
  if (
    memory < 8 * parallelism ||
    memory > MAX_ARGON2_MEMORY_KIB ||
    time > MAX_ARGON2_TIME_COST ||
    parallelism > MAX_ARGON2_PARALLELISM ||
    outputLength < 16 ||
    outputLength > 1024
  ) {
    throw new TypeError("Argon2id parameters are outside the supported bounds.");
  }
}

function validStoredArgon2Parameters(
  record: NonNullable<ReturnType<typeof parseArgon2idRecord>>
): boolean {
  return (
    record.memoryCostKiB >= 8 * record.parallelism &&
    record.memoryCostKiB <= MAX_ARGON2_MEMORY_KIB &&
    record.timeCost >= 1 &&
    record.timeCost <= MAX_ARGON2_TIME_COST &&
    record.parallelism >= 1 &&
    record.parallelism <= MAX_ARGON2_PARALLELISM &&
    record.salt.length >= 8 &&
    record.salt.length <= 1024 &&
    record.hash.length >= 16 &&
    record.hash.length <= 1024
  );
}

function parseScryptHash(value: string): {
  cost: number;
  blockSize: number;
  parallelism: number;
  salt: Uint8Array;
  hash: Uint8Array;
} | null {
  if (value.length > MAX_HASH_RECORD_LENGTH) return null;
  const match =
    /^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/u.exec(
      value
    );
  if (!match?.[1] || !match[2] || !match[3] || !match[4] || !match[5]) {
    return null;
  }
  try {
    const logCost = Number(match[1]);
    const blockSize = Number(match[2]);
    const parallelism = Number(match[3]);
    if (
      !Number.isSafeInteger(logCost) ||
      logCost < 1 ||
      logCost > 20 ||
      !Number.isSafeInteger(blockSize) ||
      blockSize < 1 ||
      blockSize > MAX_SCRYPT_BLOCK_SIZE ||
      !Number.isSafeInteger(parallelism) ||
      parallelism < 1 ||
      parallelism > MAX_SCRYPT_PARALLELISM
    ) {
      return null;
    }
    const salt = decodeBase64Url(match[4]);
    const hash = decodeBase64Url(match[5]);
    if (
      salt.length < 8 ||
      salt.length > MAX_HASH_COMPONENT_BYTES ||
      hash.length < 16 ||
      hash.length > MAX_HASH_COMPONENT_BYTES
    ) {
      return null;
    }
    return {
      cost: 2 ** logCost,
      blockSize,
      parallelism,
      salt,
      hash,
    };
  } catch {
    return null;
  }
}

function validatePassword(password: string): void {
  const length = textEncoder.encode(password).byteLength;
  if (length < 1 || length > 4_096) {
    throw new TypeError("Password must contain between 1 and 4096 bytes.");
  }
}

function positiveInteger(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError("Password hashing parameters must be positive integers.");
  }
  return value;
}
