export interface AuthUser {
  readonly id: string
  readonly email: string
  readonly createdAt: Date
}

export interface UserStore<User extends AuthUser> {
  findById(userId: string): Promise<User | null>
}

export interface ExternalIdentity {
  readonly provider: string
  readonly providerSubject: string
  readonly email?: string
  readonly emailVerified?: boolean
  readonly claims: Readonly<Record<string, unknown>>
}

export interface IdentityStore<User extends AuthUser> {
  findUser(provider: string, providerSubject: string): Promise<User | null>
  resolve(identity: ExternalIdentity): Promise<User>
}

export interface AuthSessionRecord {
  readonly tokenHash: string
  readonly userId: string
  readonly createdAt: Date
  readonly expiresAt: Date
}

export interface SessionStore {
  create(session: AuthSessionRecord): Promise<void>
  findByTokenHash(tokenHash: string): Promise<AuthSessionRecord | null>
  deleteByTokenHash(tokenHash: string): Promise<void>
}

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

export interface AuthChallengeRecord {
  readonly tokenHash: string
  readonly provider: string
  readonly kind: AuthChallengeKind
  readonly payload: Readonly<Record<string, unknown>>
  readonly createdAt: Date
  readonly expiresAt: Date
  readonly attempts: number
}

export interface ChallengeStore {
  create(challenge: AuthChallengeRecord): Promise<void>
  findByTokenHash?(tokenHash: string): Promise<AuthChallengeRecord | null>
  consumeByTokenHash(tokenHash: string): Promise<AuthChallengeRecord | null>
  incrementAttempts?(tokenHash: string, expectedAttempts: number): Promise<boolean>
}

export interface AuthChallengeToken {
  readonly token: string
  readonly expiresAt: Date
}

export interface AuthSession<User extends AuthUser> {
  readonly token: string
  readonly user: User
  readonly expiresAt: Date
}

export interface SessionToken {
  readonly token: string
  readonly expiresAt: Date
}

export type AuthEventResult = 'success' | 'rejected' | 'error'

export interface AuthEvent {
  readonly operation: string
  readonly result: AuthEventResult
  readonly provider?: string
  readonly code?: string
  readonly durationMs: number
}

export interface AuthConfig<User extends AuthUser> {
  readonly users: UserStore<User>
  readonly sessions: SessionStore
  readonly identities?: IdentityStore<User>
  readonly challenges?: ChallengeStore
  readonly sessionTtlMs?: number
  readonly challengeTtlMs?: number
  readonly clock?: () => Date
  readonly randomBytes?: (length: number) => Uint8Array
  readonly onEvent?: (event: AuthEvent) => void | Promise<void>
}

export interface AuthPluginContext<User extends AuthUser> {
  readonly users: UserStore<User>
  readonly identities?: IdentityStore<User>
  readonly now: () => Date
  readonly issueSession: (userId: string) => Promise<SessionToken>
  readonly validateSession: (token: string) => Promise<User | null>
  readonly revokeSession: (token: string) => Promise<void>
  readonly issueChallenge: (
    provider: string,
    kind: AuthChallengeKind,
    payload: Readonly<Record<string, unknown>>,
    ttlMs?: number
  ) => Promise<AuthChallengeToken>
  readonly consumeChallenge: (
    token: string,
    expectedProvider: string,
    expectedKinds?: readonly AuthChallengeKind[]
  ) => Promise<AuthChallengeRecord>
  readonly readChallenge: (
    token: string,
    expectedProvider: string,
    expectedKinds?: readonly AuthChallengeKind[]
  ) => Promise<AuthChallengeRecord>
  readonly recordChallengeFailure: (token: string, maximumAttempts?: number) => Promise<void>
  readonly hashSecret: (secret: string) => Promise<string>
  readonly randomToken: (byteLength?: number) => string
  readonly report: (event: Omit<AuthEvent, 'durationMs'> & { readonly startedAt: number }) => void
}

export interface AuthPlugin<Name extends string, Operations extends object, User extends AuthUser> {
  readonly name: Name
  install(context: AuthPluginContext<User>): Operations
}
