import { AuthError, normaliseEmailInput, validateEmail } from '@ngriffin_uk/auth-core'

import type { PasswordInput, PasswordPolicy } from './types.js'

const MAX_PASSWORD_LENGTH = 1_024

export const defaultPasswordPolicy: PasswordPolicy = {
  validate(password) {
    if (password.length < 8) {
      return 'Password must contain at least 8 characters.'
    }
    if (password.length > MAX_PASSWORD_LENGTH) {
      return 'Password must contain no more than 1024 characters.'
    }
    return null
  }
}

export function validatePasswordInput(input: PasswordInput, policy: PasswordPolicy): void {
  validateCredentialInput(input)
  const passwordError = policy.validate(input.password)
  if (passwordError) {
    throw new AuthError('invalid_input', passwordError)
  }
}

export function validateCredentialInput(input: PasswordInput): void {
  validateEmail(input.email)
  if (
    typeof input.password !== 'string' ||
    input.password.length === 0 ||
    input.password.length > MAX_PASSWORD_LENGTH
  ) {
    throw new AuthError('invalid_input', 'Password input is invalid.')
  }
}

export { normaliseEmailInput, validateEmail }
