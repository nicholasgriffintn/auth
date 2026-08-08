import type { ReactNode } from 'react'

export type AuthChallengeKind =
  | 'custom'
  | 'email_otp'
  | 'email_verification'
  | 'mfa_selection'
  | 'mfa_setup'
  | 'new_password'
  | 'password'
  | 'password_reset'
  | 'sms_mfa'
  | 'sms_otp'
  | 'software_token_mfa'
  | 'unsupported'
  | 'webauthn'

export interface AuthClientChallenge {
  readonly kind: AuthChallengeKind
  readonly continuationToken: string
  readonly expiresAt: string
  readonly parameters?: Readonly<Record<string, string | readonly string[]>>
}

export type AuthClientResult<User = unknown> =
  | {
      readonly status: 'authenticated'
      readonly user?: User
      readonly recoveryCodes?: readonly string[]
    }
  | {
      readonly status:
        | 'challenge_selection_required'
        | 'custom_challenge_required'
        | 'email_verification_required'
        | 'mfa_challenge_required'
        | 'mfa_setup_required'
        | 'new_password_required'
        | 'password_reset_required'
        | 'unsupported_challenge'
        | 'webauthn_challenge_required'
      readonly challenge: AuthClientChallenge
    }
  | {
      readonly status: 'redirect_required'
      readonly provider: string
      readonly url: string
    }
  | {
      readonly status: 'completed'
      readonly next?: AuthView
      readonly message?: string
    }

export type AuthRequest =
  | {
      readonly action: 'sign_in' | 'sign_up'
      readonly values: Readonly<Record<string, string | boolean>>
    }
  | {
      readonly action: 'start_recovery'
      readonly values: Readonly<{ email: string }>
    }
  | {
      readonly action: 'request_magic_link'
      readonly values: Readonly<{ email: string }>
    }
  | {
      readonly action: 'start_oauth'
      readonly provider: string
      readonly values?: Readonly<Record<string, string>>
    }
  | {
      readonly action: 'sign_in_direct'
      readonly provider: string
      readonly values: Readonly<Record<string, string>>
    }
  | {
      readonly action: 'start_passkey'
      readonly values: Readonly<Record<string, string>>
    }
  | { readonly action: 'start_totp_setup' }
  | { readonly action: 'start_webauthn_registration' }
  | { readonly action: 'resume_mfa' }
  | {
      readonly action: 'continue'
      readonly continuationToken: string
      readonly kind: AuthChallengeKind
      readonly values: Readonly<Record<string, string>>
    }
  | {
      readonly action: 'resend'
      readonly continuationToken: string
      readonly kind: 'email_verification'
    }
  | { readonly action: 'sign_out' }

export interface AuthTransport<User = unknown> {
  execute(request: AuthRequest): Promise<AuthClientResult<User>>
}

export type AuthView =
  | 'challenge'
  | 'forgot_password'
  | 'recovery_codes'
  | 'sign_in'
  | 'sign_up'

export interface AuthField {
  readonly name: string
  readonly label: string
  readonly type?: 'checkbox' | 'email' | 'password' | 'select' | 'text'
  readonly options?: readonly AuthFieldOption[]
  readonly autoComplete?: string
  readonly inputMode?: 'email' | 'numeric' | 'text'
  readonly placeholder?: string
  readonly description?: string
  readonly required?: boolean
  readonly minLength?: number
  readonly maxLength?: number
  readonly pattern?: string
  readonly initialValue?: string | boolean
  readonly validate?: (value: string | boolean, values: Readonly<Record<string, string | boolean>>) => string | null
}

export interface AuthFieldOption {
  readonly label: string
  readonly value: string
}

export type AuthProviderFieldPresentation = 'inline' | 'modal'

export interface ExternalAuthProvider {
  readonly id: string
  readonly label: string
  readonly icon?: ReactNode
  readonly strategy?: 'apple_direct' | 'oauth'
  readonly clientId?: string
  readonly redirectUri?: string
  readonly scope?: string
  readonly className?: string
  readonly fields?: readonly AuthField[]
  readonly values?: Readonly<Record<string, string>>
  readonly separatorBefore?: string
  readonly submitLabel?: string
  readonly formTitle?: string
  readonly formDescription?: string
}

export interface AuthCapabilities {
  readonly magicLink?: boolean
  readonly password?: boolean
  readonly passkeys?: boolean
  readonly signUp?: boolean
  readonly recovery?: boolean
  readonly signOut?: boolean
}

export interface AuthCopy {
  readonly signInTitle: string
  readonly signInDescription: string
  readonly signInSeparator: string
  readonly signInSubmit: string
  readonly signUpTitle: string
  readonly signUpSubmit: string
  readonly recoveryTitle: string
  readonly recoverySubmit: string
  readonly magicLinkSubmit: string
  readonly codeLabel: string
  readonly codeSubmit: string
  readonly passwordLabel: string
  readonly newPasswordLabel: string
  readonly confirmPasswordLabel: string
  readonly continueLabel: string
  readonly passkeyLabel: string
  readonly securityTitle: string
  readonly totpTitle: string
  readonly totpDescription: string
  readonly totpSetupLabel: string
  readonly totpConfiguredLabel: string
  readonly passkeyTitle: string
  readonly passkeyDescription: string
  readonly passkeySetupLabel: string
  readonly passkeyChallengeTitle: string
  readonly totpOrRecoveryLabel: string
  readonly totpOrRecoveryCodeLabel: string
  readonly totpOrRecoveryDescription: string
  readonly recoveryCodesTitle: string
  readonly recoveryCodesLabel: string
  readonly recoveryCodesCopyLabel: string
  readonly recoveryCodesDownloadLabel: string
  readonly cancelLabel: string
  readonly resendLabel: string
  readonly genericError: string
  readonly unsupportedChallenge: string
}

export interface AuthAnalyticsEvent {
  readonly name: 'authenticated' | 'error' | 'redirect' | 'request' | 'view'
  readonly action?: AuthRequest['action']
  readonly provider?: string
  readonly status?: AuthClientResult['status']
  readonly view?: AuthView
}

export interface AuthProviderConfig<User = unknown> {
  readonly transport?: AuthTransport<User>
  readonly endpoint?: string
  readonly initialError?: string
  readonly capabilities?: AuthCapabilities
  readonly providers?: readonly ExternalAuthProvider[]
  readonly signInFields?: readonly AuthField[]
  readonly signUpFields?: readonly AuthField[]
  readonly copy?: Partial<AuthCopy>
  readonly classNames?: Partial<Record<AuthClassName, string>>
  readonly mapError?: (error: unknown) => string
  readonly onAuthenticated?: (user: User | undefined) => void | Promise<void>
  readonly onRedirect?: (url: string, provider: string) => void | Promise<void>
  readonly onAnalytics?: (event: AuthAnalyticsEvent) => void
  readonly resolveWebAuthn?: (challenge: AuthClientChallenge) => Promise<Readonly<Record<string, string>>>
}

export type ResolvedAuthUiConfig = Pick<AuthProviderConfig, 'classNames' | 'resolveWebAuthn'> & {
  readonly capabilities: Required<AuthCapabilities>
  readonly providers: readonly ExternalAuthProvider[]
  readonly signInFields: readonly AuthField[]
  readonly signUpFields: readonly AuthField[]
  readonly copy: AuthCopy
}

export type AuthClassName =
  | 'actions'
  | 'button'
  | 'challenge'
  | 'description'
  | 'dialog'
  | 'dialogContent'
  | 'error'
  | 'field'
  | 'form'
  | 'header'
  | 'input'
  | 'label'
  | 'linkButton'
  | 'magicLinkButton'
  | 'panel'
  | 'passkeyButton'
  | 'providerButton'
  | 'providerList'
  | 'recoveryCodes'
  | 'recoveryCodesActions'
  | 'securityItem'
  | 'securityList'
  | 'separator'
  | 'signIn'
  | 'status'
  | 'title'
  | 'totpQrCode'
