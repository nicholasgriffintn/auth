import { randomBytes, sha256 } from '@ngriffin_uk/auth-crypto'
import { encodeBase32, encodeBase64Url } from '@ngriffin_uk/auth-encoding'

const textEncoder = new TextEncoder()
const RECOVERY_CODE_PATTERN = /^[a-z2-7]{16}$/u

export function validateRecoveryCodeCount(count: number): void {
  if (!Number.isSafeInteger(count) || count < 1 || count > 50) {
    throw new TypeError('Recovery code count must be between 1 and 50.')
  }
}

export function createRecoveryCodes(count: number): string[] {
  validateRecoveryCodeCount(count)
  return Array.from({ length: count }, () => {
    const value = encodeBase32(randomBytes(10)).toLowerCase()
    return `${value.slice(0, 4)}-${value.slice(4, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}`
  })
}

export async function hashRecoveryCode(code: string): Promise<string | null> {
  if (typeof code !== 'string' || code.length > 32) return null
  const normalised = code.toLowerCase().replaceAll('-', '').trim()
  if (!RECOVERY_CODE_PATTERN.test(normalised)) return null
  return encodeBase64Url(await sha256(textEncoder.encode(normalised)))
}
