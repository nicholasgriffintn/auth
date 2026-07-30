import { AuthError, toStorageError } from './errors.js'
import type {
  AuthConfig,
  AuthChallengeKind,
  AuthChallengeRecord,
  AuthChallengeToken,
  AuthEvent,
  AuthPlugin,
  AuthPluginContext,
  AuthSession,
  AuthSessionRecord,
  AuthUser,
  SessionToken
} from './types.js'
import { encodeBase64Url, expirationDate, getSecureRandomBytes, hashSecret, requireValidDate } from './utilities.js'

const DEFAULT_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1_000
const DEFAULT_CHALLENGE_TTL_MS = 10 * 60 * 1_000
const SESSION_TOKEN_BYTES = 32

type ProviderRegistry = Readonly<Record<string, object>>

interface AuthRuntime<User extends AuthUser> {
  readonly config: AuthConfig<User>
  readonly now: () => Date
  readonly randomBytes: (length: number) => Uint8Array
}

interface ResolvedSession<User extends AuthUser> {
  readonly record: AuthSessionRecord
  readonly user: User
}

export class Auth<User extends AuthUser, Providers extends ProviderRegistry = Record<never, never>> {
  readonly providers: Providers
  readonly #runtime: AuthRuntime<User>

  private constructor(runtime: AuthRuntime<User>, providers: Providers) {
    this.#runtime = runtime
    this.providers = Object.freeze({ ...providers })
  }

  static create<User extends AuthUser>(config: AuthConfig<User>): Auth<User, Record<never, never>> {
    const sessionTtlMs = config.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS
    if (!Number.isSafeInteger(sessionTtlMs) || sessionTtlMs <= 0) {
      throw new AuthError('invalid_input', 'Session lifetime must be a positive integer.')
    }
    const challengeTtlMs = config.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS
    if (!Number.isSafeInteger(challengeTtlMs) || challengeTtlMs <= 0) {
      throw new AuthError('invalid_input', 'Challenge lifetime must be a positive integer.')
    }

    return new Auth(
      {
        config,
        now: config.clock ?? (() => new Date()),
        randomBytes: config.randomBytes ?? getSecureRandomBytes
      },
      {}
    )
  }

  use<Name extends string, Operations extends object>(
    plugin: AuthPlugin<Name, Operations, User>
  ): Auth<User, Providers & Readonly<Record<Name, Operations>>> {
    if (Object.hasOwn(this.providers, plugin.name)) {
      throw new AuthError('duplicate_plugin')
    }

    const operations = plugin.install(this.#pluginContext())
    const providers = {
      ...this.providers,
      [plugin.name]: Object.freeze(operations)
    } as Providers & Readonly<Record<Name, Operations>>

    return new Auth(this.#runtime, providers)
  }

  async createSession(userId: string): Promise<SessionToken> {
    const startedAt = performance.now()
    try {
      if (typeof userId !== 'string' || userId.length === 0 || userId.length > 1_024) {
        throw new AuthError('invalid_input', 'User ID is invalid.')
      }
      const now = requireValidDate(this.#runtime.now(), 'Authentication clock')
      const token = this.#randomToken()
      const tokenHash = await hashSecret(token)
      const expiresAt = expirationDate(
        now,
        this.#runtime.config.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS,
        'Session expiry'
      )

      await this.#runtime.config.sessions.create({
        tokenHash,
        userId,
        createdAt: now,
        expiresAt
      })
      this.#report({
        operation: 'session.create',
        result: 'success',
        startedAt
      })
      return { token, expiresAt }
    } catch (cause) {
      this.#report({
        operation: 'session.create',
        result: 'error',
        code: cause instanceof AuthError ? cause.code : 'storage_error',
        startedAt
      })
      throw toStorageError(cause)
    }
  }

  async validateSession(token: string): Promise<User | null> {
    const resolved = await this.#validateSessionRecord(token)
    return resolved?.user ?? null
  }

  async authenticate(token: string): Promise<AuthSession<User> | null> {
    const resolved = await this.#validateSessionRecord(token)
    return resolved
      ? {
          token,
          user: resolved.user,
          expiresAt: resolved.record.expiresAt
        }
      : null
  }

  async #validateSessionRecord(token: string): Promise<ResolvedSession<User> | null> {
    const startedAt = performance.now()
    try {
      if (!isValidSecret(token)) {
        this.#report({
          operation: 'session.validate',
          result: 'rejected',
          code: 'session_expired',
          startedAt
        })
        return null
      }
      const tokenHash = await hashSecret(token)
      const record = await this.#runtime.config.sessions.findByTokenHash(tokenHash)
      if (!record) {
        this.#report({
          operation: 'session.validate',
          result: 'rejected',
          code: 'session_expired',
          startedAt
        })
        return null
      }

      const expiresAt = record.expiresAt instanceof Date ? record.expiresAt.getTime() : Number.NaN
      const now = requireValidDate(this.#runtime.now(), 'Authentication clock').getTime()
      if (!Number.isFinite(expiresAt) || expiresAt <= now) {
        await this.#runtime.config.sessions.deleteByTokenHash(tokenHash)
        this.#report({
          operation: 'session.validate',
          result: 'rejected',
          code: 'session_expired',
          startedAt
        })
        return null
      }

      const user = await this.#runtime.config.users.findById(record.userId)
      if (!user) {
        await this.#runtime.config.sessions.deleteByTokenHash(tokenHash)
        this.#report({
          operation: 'session.validate',
          result: 'rejected',
          code: 'session_expired',
          startedAt
        })
        return null
      }

      this.#report({
        operation: 'session.validate',
        result: 'success',
        startedAt
      })
      return { record, user }
    } catch (cause) {
      this.#report({
        operation: 'session.validate',
        result: 'error',
        code: cause instanceof AuthError ? cause.code : 'storage_error',
        startedAt
      })
      throw toStorageError(cause)
    }
  }

  async revokeSession(token: string): Promise<void> {
    if (!isValidSecret(token)) return
    try {
      const tokenHash = await hashSecret(token)
      await this.#runtime.config.sessions.deleteByTokenHash(tokenHash)
    } catch (cause) {
      throw toStorageError(cause)
    }
  }

  async issueChallenge(
    provider: string,
    kind: AuthChallengeKind,
    payload: Readonly<Record<string, unknown>>,
    ttlMs = this.#runtime.config.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS
  ): Promise<AuthChallengeToken> {
    const store = this.#runtime.config.challenges
    if (!store) {
      throw new AuthError('unsupported_operation', 'A challenge store is required for this authentication flow.')
    }
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
      throw new AuthError('invalid_input', 'Challenge lifetime must be a positive integer.')
    }
    if (typeof provider !== 'string' || provider.length === 0 || provider.length > 128) {
      throw new AuthError('invalid_input', 'Challenge provider is invalid.')
    }

    try {
      const token = this.#randomToken()
      const tokenHash = await hashSecret(token)
      const createdAt = requireValidDate(this.#runtime.now(), 'Authentication clock')
      const expiresAt = expirationDate(createdAt, ttlMs, 'Challenge expiry')
      await store.create({
        tokenHash,
        provider,
        kind,
        payload,
        createdAt,
        expiresAt,
        attempts: 0
      })
      return { token, expiresAt }
    } catch (cause) {
      throw toStorageError(cause)
    }
  }

  async consumeChallenge(
    token: string,
    expectedProvider: string,
    expectedKinds?: readonly AuthChallengeKind[]
  ): Promise<AuthChallengeRecord> {
    const store = this.#runtime.config.challenges
    if (!store) {
      throw new AuthError('unsupported_operation', 'A challenge store is required for this authentication flow.')
    }
    if (!isValidSecret(token)) {
      throw new AuthError('challenge_expired')
    }

    let record: AuthChallengeRecord | null
    try {
      record = await store.consumeByTokenHash(await hashSecret(token))
    } catch (cause) {
      throw toStorageError(cause)
    }

    return this.#validateChallengeRecord(record, expectedProvider, expectedKinds)
  }

  async readChallenge(
    token: string,
    expectedProvider: string,
    expectedKinds?: readonly AuthChallengeKind[]
  ): Promise<AuthChallengeRecord> {
    const store = this.#runtime.config.challenges
    if (!store?.findByTokenHash) {
      throw new AuthError('unsupported_operation', 'This challenge store does not support retryable challenges.')
    }
    if (!isValidSecret(token)) {
      throw new AuthError('challenge_expired')
    }

    let record: AuthChallengeRecord | null
    try {
      record = await store.findByTokenHash(await hashSecret(token))
    } catch (cause) {
      throw toStorageError(cause)
    }
    return this.#validateChallengeRecord(record, expectedProvider, expectedKinds)
  }

  async recordChallengeFailure(token: string, maximumAttempts = 5): Promise<void> {
    const store = this.#runtime.config.challenges
    if (!store || !isValidSecret(token)) return
    if (!Number.isSafeInteger(maximumAttempts) || maximumAttempts < 1 || maximumAttempts > 100) {
      throw new AuthError('invalid_input', 'Challenge attempt limit is invalid.')
    }
    try {
      const tokenHash = await hashSecret(token)
      const record = store.findByTokenHash ? await store.findByTokenHash(tokenHash) : null
      if (!record) return
      if (record.attempts + 1 >= maximumAttempts || !store.incrementAttempts) {
        await store.consumeByTokenHash(tokenHash)
        return
      }
      if (!(await store.incrementAttempts(tokenHash, record.attempts))) {
        throw new AuthError('challenge_expired')
      }
    } catch (cause) {
      if (cause instanceof AuthError) throw cause
      throw toStorageError(cause)
    }
  }

  #validateChallengeRecord(
    record: AuthChallengeRecord | null,
    expectedProvider: string,
    expectedKinds?: readonly AuthChallengeKind[]
  ): AuthChallengeRecord {
    const now = requireValidDate(this.#runtime.now(), 'Authentication clock').getTime()
    if (
      !record ||
      !(record.expiresAt instanceof Date) ||
      !Number.isFinite(record.expiresAt.getTime()) ||
      record.expiresAt.getTime() <= now
    ) {
      throw new AuthError('challenge_expired')
    }
    if (record.provider !== expectedProvider || (expectedKinds && !expectedKinds.includes(record.kind))) {
      throw new AuthError('challenge_mismatch')
    }
    return record
  }

  #randomToken(byteLength = SESSION_TOKEN_BYTES): string {
    if (!Number.isSafeInteger(byteLength) || byteLength < 1 || byteLength > 4_096) {
      throw new AuthError('invalid_input', 'Random byte length is invalid.')
    }
    const bytes = this.#runtime.randomBytes(byteLength)
    if (!(bytes instanceof Uint8Array) || bytes.length !== byteLength) {
      throw new AuthError('insecure_runtime', 'The secure random source returned invalid output.')
    }
    return encodeBase64Url(bytes)
  }

  #pluginContext(): AuthPluginContext<User> {
    const context: AuthPluginContext<User> = {
      users: this.#runtime.config.users,
      ...(this.#runtime.config.identities ? { identities: this.#runtime.config.identities } : {}),
      now: this.#runtime.now,
      issueSession: (userId: string) => this.createSession(userId),
      validateSession: (token: string) => this.validateSession(token),
      revokeSession: (token: string) => this.revokeSession(token),
      issueChallenge: (
        provider: string,
        kind: AuthChallengeKind,
        payload: Readonly<Record<string, unknown>>,
        ttlMs?: number
      ) => this.issueChallenge(provider, kind, payload, ttlMs),
      consumeChallenge: (token: string, expectedProvider: string, expectedKinds?: readonly AuthChallengeKind[]) =>
        this.consumeChallenge(token, expectedProvider, expectedKinds),
      readChallenge: (token: string, expectedProvider: string, expectedKinds?: readonly AuthChallengeKind[]) =>
        this.readChallenge(token, expectedProvider, expectedKinds),
      recordChallengeFailure: (token: string, maximumAttempts?: number) =>
        this.recordChallengeFailure(token, maximumAttempts),
      hashSecret,
      randomToken: (byteLength?: number) => this.#randomToken(byteLength),
      report: (event) => this.#report(event)
    }
    return Object.freeze(context)
  }

  #report(event: Omit<AuthEvent, 'durationMs'> & { readonly startedAt: number }): void {
    const { startedAt, ...details } = event
    const callback = this.#runtime.config.onEvent
    if (!callback) {
      return
    }
    try {
      const result = callback({
        ...details,
        durationMs: Math.max(0, performance.now() - startedAt)
      })
      if (result !== undefined) {
        void Promise.resolve(result).catch(() => undefined)
      }
    } catch {
      // Telemetry must never change authentication behaviour.
    }
  }
}

function isValidSecret(value: string): boolean {
  return typeof value === 'string' && value.length > 0 && value.length <= 4_096
}

export function createAuth<User extends AuthUser>(config: AuthConfig<User>): Auth<User> {
  return Auth.create(config)
}
