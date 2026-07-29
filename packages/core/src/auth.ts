import { AuthError, toStorageError } from "./errors.js";
import type {
  AuthConfig,
  AuthChallengeKind,
  AuthChallengeRecord,
  AuthChallengeToken,
  AuthEvent,
  AuthPlugin,
  AuthPluginContext,
  AuthSession,
  AuthUser,
  SessionToken,
} from "./types.js";
import {
  encodeBase64Url,
  getSecureRandomBytes,
  hashSecret,
} from "./utilities.js";

const DEFAULT_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1_000;
const DEFAULT_CHALLENGE_TTL_MS = 10 * 60 * 1_000;
const SESSION_TOKEN_BYTES = 32;

type ProviderRegistry = Readonly<Record<string, object>>;

interface AuthRuntime<User extends AuthUser> {
  readonly config: AuthConfig<User>;
  readonly now: () => Date;
  readonly randomBytes: (length: number) => Uint8Array;
}

export class Auth<
  User extends AuthUser,
  Providers extends ProviderRegistry = Record<never, never>,
> {
  readonly providers: Providers;
  readonly #runtime: AuthRuntime<User>;

  private constructor(runtime: AuthRuntime<User>, providers: Providers) {
    this.#runtime = runtime;
    this.providers = Object.freeze({ ...providers });
  }

  static create<User extends AuthUser>(
    config: AuthConfig<User>
  ): Auth<User, Record<never, never>> {
    const sessionTtlMs = config.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
    if (!Number.isSafeInteger(sessionTtlMs) || sessionTtlMs <= 0) {
      throw new AuthError(
        "invalid_input",
        "Session lifetime must be a positive integer."
      );
    }
    const challengeTtlMs = config.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS;
    if (!Number.isSafeInteger(challengeTtlMs) || challengeTtlMs <= 0) {
      throw new AuthError(
        "invalid_input",
        "Challenge lifetime must be a positive integer."
      );
    }

    return new Auth(
      {
        config,
        now: config.clock ?? (() => new Date()),
        randomBytes: config.randomBytes ?? getSecureRandomBytes,
      },
      {}
    );
  }

  use<Name extends string, Operations extends object>(
    plugin: AuthPlugin<Name, Operations, User>
  ): Auth<User, Providers & Readonly<Record<Name, Operations>>> {
    if (Object.hasOwn(this.providers, plugin.name)) {
      throw new AuthError("duplicate_plugin");
    }

    const operations = plugin.install(this.#pluginContext());
    const providers = {
      ...this.providers,
      [plugin.name]: Object.freeze(operations),
    } as Providers & Readonly<Record<Name, Operations>>;

    return new Auth(this.#runtime, providers);
  }

  async createSession(userId: string): Promise<SessionToken> {
    const startedAt = performance.now();
    try {
      const now = this.#runtime.now();
      const token = this.#randomToken();
      const tokenHash = await hashSecret(token);
      const expiresAt = new Date(
        now.getTime() +
          (this.#runtime.config.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS)
      );

      await this.#runtime.config.sessions.create({
        tokenHash,
        userId,
        createdAt: now,
        expiresAt,
      });
      this.#report({
        operation: "session.create",
        result: "success",
        startedAt,
      });
      return { token, expiresAt };
    } catch (cause) {
      this.#report({
        operation: "session.create",
        result: "error",
        code: cause instanceof AuthError ? cause.code : "storage_error",
        startedAt,
      });
      throw toStorageError(cause);
    }
  }

  async validateSession(token: string): Promise<User | null> {
    const startedAt = performance.now();
    try {
      const tokenHash = await hashSecret(token);
      const record =
        await this.#runtime.config.sessions.findByTokenHash(tokenHash);
      if (!record) {
        this.#report({
          operation: "session.validate",
          result: "rejected",
          code: "session_expired",
          startedAt,
        });
        return null;
      }

      if (record.expiresAt.getTime() <= this.#runtime.now().getTime()) {
        await this.#runtime.config.sessions.deleteByTokenHash(tokenHash);
        this.#report({
          operation: "session.validate",
          result: "rejected",
          code: "session_expired",
          startedAt,
        });
        return null;
      }

      const user = await this.#runtime.config.users.findById(record.userId);
      if (!user) {
        await this.#runtime.config.sessions.deleteByTokenHash(tokenHash);
        this.#report({
          operation: "session.validate",
          result: "rejected",
          code: "session_expired",
          startedAt,
        });
        return null;
      }

      this.#report({
        operation: "session.validate",
        result: "success",
        startedAt,
      });
      return user;
    } catch (cause) {
      this.#report({
        operation: "session.validate",
        result: "error",
        code: cause instanceof AuthError ? cause.code : "storage_error",
        startedAt,
      });
      throw toStorageError(cause);
    }
  }

  async authenticate(token: string): Promise<AuthSession<User> | null> {
    const user = await this.validateSession(token);
    if (!user) {
      return null;
    }
    const tokenHash = await hashSecret(token);
    const record =
      await this.#runtime.config.sessions.findByTokenHash(tokenHash);
    if (!record) {
      return null;
    }
    return { token, user, expiresAt: record.expiresAt };
  }

  async revokeSession(token: string): Promise<void> {
    try {
      const tokenHash = await hashSecret(token);
      await this.#runtime.config.sessions.deleteByTokenHash(tokenHash);
    } catch (cause) {
      throw toStorageError(cause);
    }
  }

  async issueChallenge(
    provider: string,
    kind: AuthChallengeKind,
    payload: Readonly<Record<string, unknown>>,
    ttlMs = this.#runtime.config.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS
  ): Promise<AuthChallengeToken> {
    const store = this.#runtime.config.challenges;
    if (!store) {
      throw new AuthError(
        "unsupported_operation",
        "A challenge store is required for this authentication flow."
      );
    }
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
      throw new AuthError(
        "invalid_input",
        "Challenge lifetime must be a positive integer."
      );
    }

    try {
      const token = this.#randomToken();
      const tokenHash = await hashSecret(token);
      const createdAt = this.#runtime.now();
      const expiresAt = new Date(createdAt.getTime() + ttlMs);
      await store.create({
        tokenHash,
        provider,
        kind,
        payload,
        createdAt,
        expiresAt,
        attempts: 0,
      });
      return { token, expiresAt };
    } catch (cause) {
      throw toStorageError(cause);
    }
  }

  async consumeChallenge(
    token: string,
    expectedProvider: string,
    expectedKinds?: readonly AuthChallengeKind[]
  ): Promise<AuthChallengeRecord> {
    const store = this.#runtime.config.challenges;
    if (!store) {
      throw new AuthError(
        "unsupported_operation",
        "A challenge store is required for this authentication flow."
      );
    }

    let record: AuthChallengeRecord | null;
    try {
      record = await store.consumeByTokenHash(await hashSecret(token));
    } catch (cause) {
      throw toStorageError(cause);
    }

    if (!record || record.expiresAt.getTime() <= this.#runtime.now().getTime()) {
      throw new AuthError("challenge_expired");
    }
    if (
      record.provider !== expectedProvider ||
      (expectedKinds && !expectedKinds.includes(record.kind))
    ) {
      throw new AuthError("challenge_mismatch");
    }
    return record;
  }

  #randomToken(byteLength = SESSION_TOKEN_BYTES): string {
    return encodeBase64Url(this.#runtime.randomBytes(byteLength));
  }

  #pluginContext(): AuthPluginContext<User> {
    const context: AuthPluginContext<User> = {
      users: this.#runtime.config.users,
      ...(this.#runtime.config.identities
        ? { identities: this.#runtime.config.identities }
        : {}),
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
      consumeChallenge: (
        token: string,
        expectedProvider: string,
        expectedKinds?: readonly AuthChallengeKind[]
      ) => this.consumeChallenge(token, expectedProvider, expectedKinds),
      hashSecret,
      randomToken: (byteLength?: number) => this.#randomToken(byteLength),
      report: (event) => this.#report(event),
    };
    return Object.freeze(context);
  }

  #report(
    event: Omit<AuthEvent, "durationMs"> & { readonly startedAt: number }
  ): void {
    const { startedAt, ...details } = event;
    const callback = this.#runtime.config.onEvent;
    if (!callback) {
      return;
    }
    try {
      const result = callback({
        ...details,
        durationMs: Math.max(0, performance.now() - startedAt),
      });
      if (result instanceof Promise) {
        void result.catch(() => undefined);
      }
    } catch {
      // Telemetry must never change authentication behaviour.
    }
  }
}

export function createAuth<User extends AuthUser>(
  config: AuthConfig<User>
): Auth<User> {
  return Auth.create(config);
}
