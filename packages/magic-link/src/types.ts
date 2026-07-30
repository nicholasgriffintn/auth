import type { AuthFlowResult, AuthUser } from '@ngriffin_uk/auth-core'

export type MagicLinkDeliveryMode = 'code' | 'link'

export interface MagicLinkDelivery {
  readonly email: string
  readonly mode: MagicLinkDeliveryMode
  readonly token: string
  readonly expiresAt: Date
}

export interface MagicLinkPluginConfig<User extends AuthUser> {
  readonly mode?: MagicLinkDeliveryMode
  readonly resolveUser: (email: string) => Promise<User | null>
  readonly send: (delivery: MagicLinkDelivery) => Promise<void>
  readonly normaliseEmail?: (email: string) => string
  readonly codeLength?: number
}

export interface MagicLinkOperations<User extends AuthUser> {
  request(email: string): Promise<AuthFlowResult<User> | void>
  verify(input: { readonly token: string; readonly code?: string }): Promise<User>
  authenticate(input: { readonly token: string; readonly code?: string }): Promise<AuthFlowResult<User>>
}
