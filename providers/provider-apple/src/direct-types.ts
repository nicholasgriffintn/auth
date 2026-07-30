import type { AuthFlowResult, AuthUser } from '@ngriffin_uk/auth-core'

export interface AppleDirectOptions {
  readonly clientIds: readonly string[]
  readonly fetch?: typeof globalThis.fetch
}

export interface AppleDirectSignInInput {
  readonly identityToken: string
  readonly nonce: string
  readonly name?: string
}

export interface AppleDirectOperations<User extends AuthUser> {
  signIn(input: AppleDirectSignInInput): Promise<AuthFlowResult<User>>
}
