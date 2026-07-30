import {
  signEcdsa,
  signHmac,
  signRsaPkcs1,
  signRsaPss,
  verifyEcdsa,
  verifyHmac,
  verifyRsaPkcs1,
  verifyRsaPss,
  type Sha2Algorithm
} from '@ngriffin_uk/auth-crypto'

import { JwtError } from './error.js'
import type { JwtAlgorithm } from './types.js'

const textEncoder = new TextEncoder()

export function isJwtAlgorithm(value: string): value is JwtAlgorithm {
  return /^(?:ES|HS|PS|RS)(?:256|384|512)$/u.test(value)
}

export function sign(algorithm: JwtAlgorithm, key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  assertKeyMatchesAlgorithm(algorithm, key)
  const hash = getHash(algorithm)
  if (algorithm.startsWith('HS')) return signHmac(hash, key, data)
  if (algorithm.startsWith('RS')) return signRsaPkcs1(key, data)
  if (algorithm.startsWith('PS')) {
    return signRsaPss(key, data, getHashByteLength(hash))
  }
  return signEcdsa(key, data, hash)
}

export function verify(
  algorithm: JwtAlgorithm,
  key: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  assertKeyMatchesAlgorithm(algorithm, key)
  const hash = getHash(algorithm)
  if (algorithm.startsWith('HS')) {
    return verifyHmac(hash, key, signature, data)
  }
  if (algorithm.startsWith('RS')) {
    return verifyRsaPkcs1(key, signature, data)
  }
  if (algorithm.startsWith('PS')) {
    return verifyRsaPss(key, signature, data, getHashByteLength(hash))
  }
  return verifyEcdsa(key, signature, data, hash)
}

export async function importJwk(jwk: JsonWebKey, algorithm: JwtAlgorithm): Promise<CryptoKey> {
  const hash = getHash(algorithm)
  const subtle = globalThis.crypto?.subtle
  if (!subtle) throw new Error('Web Crypto is unavailable.')

  if (algorithm.startsWith('HS')) {
    return subtle.importKey('jwk', jwk, { name: 'HMAC', hash }, false, ['verify'])
  }
  if (algorithm.startsWith('RS')) {
    return subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify'])
  }
  if (algorithm.startsWith('PS')) {
    return subtle.importKey('jwk', jwk, { name: 'RSA-PSS', hash }, false, ['verify'])
  }
  return subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: getCurve(algorithm) }, false, ['verify'])
}

export async function importHmacSecret(
  secret: string,
  algorithm: 'HS256' | 'HS384' | 'HS512' = 'HS256'
): Promise<CryptoKey> {
  if (typeof secret !== 'string') {
    throw new TypeError('HMAC secret is invalid.')
  }
  const bytes = textEncoder.encode(secret)
  if (bytes.length < 32 || bytes.length > 16_384) {
    throw new TypeError('HMAC secret must contain between 32 and 16384 bytes.')
  }
  const subtle = globalThis.crypto?.subtle
  if (!subtle) throw new Error('Web Crypto is unavailable.')
  return subtle.importKey('raw', bytes, { name: 'HMAC', hash: getHash(algorithm) }, false, ['sign', 'verify'])
}

export function encodeJson(value: unknown): Uint8Array {
  return textEncoder.encode(JSON.stringify(value))
}

function getHash(algorithm: JwtAlgorithm): Sha2Algorithm {
  if (algorithm.endsWith('256')) return 'SHA-256'
  if (algorithm.endsWith('384')) return 'SHA-384'
  return 'SHA-512'
}

function getHashByteLength(algorithm: Sha2Algorithm): number {
  if (algorithm === 'SHA-256') return 32
  if (algorithm === 'SHA-384') return 48
  return 64
}

function getCurve(algorithm: JwtAlgorithm): 'P-256' | 'P-384' | 'P-521' {
  if (algorithm === 'ES256') return 'P-256'
  if (algorithm === 'ES384') return 'P-384'
  return 'P-521'
}

function assertKeyMatchesAlgorithm(algorithm: JwtAlgorithm, key: CryptoKey): void {
  const expectedName = algorithm.startsWith('HS')
    ? 'HMAC'
    : algorithm.startsWith('RS')
    ? 'RSASSA-PKCS1-v1_5'
    : algorithm.startsWith('PS')
    ? 'RSA-PSS'
    : 'ECDSA'
  const keyAlgorithm = key.algorithm
  const hash = readNestedName(keyAlgorithm, 'hash')
  const curve = readString(keyAlgorithm, 'namedCurve')
  const valid =
    keyAlgorithm.name === expectedName &&
    (algorithm.startsWith('ES') ? curve === getCurve(algorithm) : hash === getHash(algorithm))

  if (!valid) {
    throw new JwtError('invalid_key', `JWT key parameters do not match ${algorithm}.`)
  }
}

function readNestedName(value: object, property: string): string | undefined {
  const nested = Reflect.get(value, property)
  return typeof nested === 'object' && nested !== null ? readString(nested, 'name') : undefined
}

function readString(value: object, property: string): string | undefined {
  const result = Reflect.get(value, property)
  return typeof result === 'string' ? result : undefined
}
