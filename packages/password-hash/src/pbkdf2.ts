import { constantTimeEqual, randomBytes } from '@ngriffin_uk/auth-crypto'
import { decodeBase64Url, encodeBase64Url } from '@ngriffin_uk/auth-encoding'

import type { UpgradeablePasswordHasher } from './index.js'

const DEFAULT_ITERATIONS = 600_000
const DEFAULT_SALT_BYTES = 16
const DEFAULT_KEY_BYTES = 32
const MAX_HASH_RECORD_LENGTH = 16_384
const MAX_ITERATIONS = 2_000_000
const MAX_SALT_BYTES = 1024
const MAX_KEY_BYTES = 1024
const HASH_PATTERN = /^\$pbkdf2-sha256\$i=(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/u
const textEncoder = new TextEncoder()

export interface Pbkdf2Options {
  readonly iterations?: number
  readonly saltBytes?: number
  readonly keyBytes?: number
}

export function createPbkdf2Hasher(options: Pbkdf2Options = {}): UpgradeablePasswordHasher {
  const iterations = positiveInteger(options.iterations ?? DEFAULT_ITERATIONS, 'PBKDF2 iterations')
  const saltBytes = positiveInteger(options.saltBytes ?? DEFAULT_SALT_BYTES, 'PBKDF2 salt bytes')
  const keyBytes = positiveInteger(options.keyBytes ?? DEFAULT_KEY_BYTES, 'PBKDF2 key bytes')
  if (iterations > MAX_ITERATIONS || saltBytes > MAX_SALT_BYTES || keyBytes < 16 || keyBytes > MAX_KEY_BYTES) {
    throw new TypeError('PBKDF2 parameters are outside the supported bounds.')
  }

  return {
    async hash(password) {
      validatePassword(password)
      const salt = randomBytes(saltBytes)
      const derived = await derive(password, salt, iterations, keyBytes)
      return `$pbkdf2-sha256$i=${iterations}$${encodeBase64Url(salt)}$${encodeBase64Url(derived)}`
    },
    async verify(password, passwordHash) {
      return (await this.verifyAndCheck(password, passwordHash)).valid
    },
    async verifyAndCheck(password, passwordHash) {
      validatePassword(password)
      const parsed = parseHash(passwordHash)
      if (!parsed) {
        return { valid: false, needsRehash: false }
      }
      const derived = await derive(password, parsed.salt, parsed.iterations, parsed.hash.length)
      const valid = constantTimeEqual(derived, parsed.hash)
      return {
        valid,
        needsRehash:
          valid &&
          (parsed.iterations !== iterations || parsed.salt.length !== saltBytes || parsed.hash.length !== keyBytes)
      }
    }
  }
}

async function derive(password: string, salt: Uint8Array, iterations: number, keyBytes: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    Uint8Array.from(textEncoder.encode(password)).buffer,
    'PBKDF2',
    false,
    ['deriveBits']
  )
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: Uint8Array.from(salt).buffer,
      iterations
    },
    key,
    keyBytes * 8
  )
  return new Uint8Array(bits)
}

function parseHash(value: string): {
  iterations: number
  salt: Uint8Array
  hash: Uint8Array
} | null {
  if (value.length > MAX_HASH_RECORD_LENGTH) return null
  const match = HASH_PATTERN.exec(value)
  if (!match?.[1] || !match[2] || !match[3]) return null
  try {
    const iterations = Number(match[1])
    if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > MAX_ITERATIONS) {
      return null
    }
    const salt = decodeBase64Url(match[2])
    const hash = decodeBase64Url(match[3])
    if (salt.length < 8 || salt.length > MAX_SALT_BYTES || hash.length < 16 || hash.length > MAX_KEY_BYTES) {
      return null
    }
    return { iterations, salt, hash }
  } catch {
    return null
  }
}

function validatePassword(password: string): void {
  if (!password || textEncoder.encode(password).byteLength > 4_096) {
    throw new TypeError('Password must contain between 1 and 4096 bytes.')
  }
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${label} must be a positive integer.`)
  }
  return value
}
