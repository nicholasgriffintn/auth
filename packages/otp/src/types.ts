import type { AuthFlowResult, AuthUser } from '@ngriffin_uk/auth-core'

import type { TotpOptions } from './totp.js'

export interface OtpCredential {
  readonly secret: Uint8Array
  readonly lastAcceptedStep?: bigint
}

export interface OtpStore {
  saveCredential(input: {
    readonly userId: string
    readonly secret: Uint8Array
    readonly lastAcceptedStep: bigint
    readonly recoveryCodeHashes: readonly string[]
  }): Promise<void>
  findCredential(userId: string): Promise<OtpCredential | null>
  advanceStep(userId: string, step: bigint): Promise<boolean>
  consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean>
}

export interface OtpPluginConfig {
  readonly issuer: string
  readonly store: OtpStore
  readonly options?: TotpOptions
  readonly recoveryCodeCount?: number
}

export interface OtpOperations<User extends AuthUser> {
  startSetup(input: { readonly userId: string; readonly accountName: string }): Promise<AuthFlowResult<User>>
  verifySetup(input: {
    readonly token: string
    readonly code: string
    readonly expectedUserId?: string
  }): Promise<AuthFlowResult<User>>
  createChallenge(userId: string): Promise<AuthFlowResult<User>>
  verifyChallenge(input: { readonly token: string; readonly code: string }): Promise<AuthFlowResult<User>>
  useRecoveryCode(input: { readonly token: string; readonly code: string }): Promise<AuthFlowResult<User>>
  verifyRecoveryCode(input: { readonly token: string; readonly code: string }): Promise<User>
}
