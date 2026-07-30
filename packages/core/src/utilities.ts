import { AuthError } from './errors.js'

const textEncoder = new TextEncoder()

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function normaliseEmail(email: string): string {
  return email.trim().toLocaleLowerCase('en-US')
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u

export function validateEmail(email: string): void {
  if (typeof email !== 'string' || !EMAIL_PATTERN.test(email) || email.length > 320) {
    throw new AuthError('invalid_input', 'Enter a valid email address.')
  }
}

export function normaliseEmailInput(email: string, normalise: (value: string) => string = normaliseEmail): string {
  if (typeof email !== 'string' || email.length === 0 || email.length > 1_024) {
    throw new AuthError('invalid_input', 'Enter a valid email address.')
  }
  let normalised: string
  try {
    normalised = normalise(email)
  } catch (cause) {
    throw new AuthError('invalid_input', 'Enter a valid email address.', {
      cause
    })
  }
  validateEmail(normalised)
  return normalised
}

export function getSecureRandomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 1) {
    throw new AuthError('invalid_input', 'Random byte length must be positive.')
  }
  if (!globalThis.crypto?.getRandomValues) {
    throw new AuthError('insecure_runtime')
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length))
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

export async function hashSecret(secret: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new AuthError('insecure_runtime')
  }
  const digest = await globalThis.crypto.subtle.digest('SHA-256', textEncoder.encode(secret))
  return encodeBase64Url(new Uint8Array(digest))
}

export function requireValidDate(value: Date, field: string): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new AuthError('invalid_input', `${field} must be a valid date.`)
  }
  return value
}

export function expirationDate(createdAt: Date, ttlMs: number, field: string): Date {
  const expiresAt = new Date(createdAt.getTime() + ttlMs)
  return requireValidDate(expiresAt, field)
}
