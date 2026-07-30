import { DurableObject } from "cloudflare:workers";
import {
  isRecord,
  type AuthChallengeKind,
  type AuthSessionRecord,
  type ExternalIdentity,
} from "@ngriffin_uk/auth-core";
import type { OAuthStateRecord } from "@ngriffin_uk/auth-oauth2";
import type {
  CreatePasswordAccountInput,
  PasswordAccount,
} from "@ngriffin_uk/auth-password";
import type { WebAuthnCredential } from "@ngriffin_uk/auth-webauthn";

import type { EncryptedValue } from "./encryption";
import type { DemoUser, Env } from "./types";

export interface StoredChallengeRecord {
  readonly tokenHash: string;
  readonly provider: string;
  readonly kind: AuthChallengeKind;
  readonly payload: EncryptedValue;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly attempts: number;
}

export interface StoredOtpCredential {
  readonly userId: string;
  readonly secret: EncryptedValue;
  readonly lastAcceptedStep: string;
  readonly recoveryCodeHashes: readonly string[];
}

interface UserRow extends Record<string, SqlStorageValue> {
  readonly id: string;
  readonly email: string;
  readonly display_name: string;
  readonly avatar_url: string | null;
  readonly provider: string;
  readonly created_at: number;
}

interface SessionRow extends Record<string, SqlStorageValue> {
  readonly token_hash: string;
  readonly user_id: string;
  readonly created_at: number;
  readonly expires_at: number;
}

interface PasswordAccountRow extends UserRow {
  readonly password_hash: string;
  readonly email_verified: number;
}

interface ChallengeRow extends Record<string, SqlStorageValue> {
  readonly token_hash: string;
  readonly provider: string;
  readonly kind: string;
  readonly payload_ciphertext: string;
  readonly payload_iv: string;
  readonly created_at: number;
  readonly expires_at: number;
  readonly attempts: number;
}

interface OtpCredentialRow extends Record<string, SqlStorageValue> {
  readonly user_id: string;
  readonly secret_ciphertext: string;
  readonly secret_iv: string;
  readonly last_accepted_step: string;
  readonly recovery_code_hashes_json: string;
}

interface WebAuthnCredentialRow extends Record<string, SqlStorageValue> {
  readonly id: string;
  readonly user_id: string;
  readonly public_key_jwk_json: string;
  readonly algorithm: string;
  readonly sign_count: number;
  readonly transports_json: string | null;
  readonly backup_eligible: number;
  readonly backed_up: number;
  readonly created_at: number;
  readonly updated_at: number;
}

interface StateRow extends Record<string, SqlStorageValue> {
  readonly state_hash: string;
  readonly provider: string;
  readonly code_verifier: string | null;
  readonly nonce: string | null;
  readonly redirect_uri: string | null;
  readonly created_at: number;
  readonly expires_at: number;
}

const CLEANUP_INTERVAL_MS = 60_000;
const MAX_IDENTITY_CLAIMS_LENGTH = 64 * 1_024;
const MAX_WEBAUTHN_CREDENTIALS_PER_USER = 10;
const MAX_WEBAUTHN_JSON_LENGTH = 32 * 1_024;
const textEncoder = new TextEncoder();

const schema = `
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    avatar_url TEXT,
    provider TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS identities (
    provider TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT,
    email_verified INTEGER,
    claims_json TEXT NOT NULL,
    PRIMARY KEY (provider, provider_subject)
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_by_user ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS sessions_by_expiry ON sessions(expires_at);
  CREATE TABLE IF NOT EXISTS password_accounts (
    email TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    email_verified INTEGER NOT NULL CHECK (email_verified IN (0, 1))
  );
  CREATE TABLE IF NOT EXISTS auth_challenges (
    token_hash TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_ciphertext TEXT NOT NULL,
    payload_iv TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS auth_challenges_by_expiry
    ON auth_challenges(expires_at);
  CREATE TABLE IF NOT EXISTS otp_credentials (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext TEXT NOT NULL,
    secret_iv TEXT NOT NULL,
    last_accepted_step TEXT NOT NULL,
    recovery_code_hashes_json TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key_jwk_json TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    sign_count INTEGER NOT NULL,
    transports_json TEXT,
    backup_eligible INTEGER NOT NULL CHECK (backup_eligible IN (0, 1)),
    backed_up INTEGER NOT NULL CHECK (backed_up IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS webauthn_credentials_by_user
    ON webauthn_credentials(user_id);
  CREATE TABLE IF NOT EXISTS oauth_states (
    state_hash TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    code_verifier TEXT,
    nonce TEXT,
    redirect_uri TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS oauth_states_by_expiry ON oauth_states(expires_at);
`;

export class AuthStore extends DurableObject<Env> {
  #nextCleanupAt = 0;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.ctx.storage.sql.exec(schema);
  }

  findUser(userId: string): DemoUser | null {
    const row = first(
      this.ctx.storage.sql.exec<UserRow>(
        "SELECT * FROM users WHERE id = ? LIMIT 1",
        userId,
      ),
    );
    return row ? mapUser(row) : null;
  }

  findUserByIdentity(
    provider: string,
    providerSubject: string,
  ): DemoUser | null {
    const row = first(
      this.ctx.storage.sql.exec<UserRow>(
        `SELECT users.*
         FROM identities
         JOIN users ON users.id = identities.user_id
         WHERE identities.provider = ? AND identities.provider_subject = ?
         LIMIT 1`,
        provider,
        providerSubject,
      ),
    );
    return row ? mapUser(row) : null;
  }

  resolveIdentity(identity: ExternalIdentity): DemoUser {
    const existing = this.findUserByIdentity(
      identity.provider,
      identity.providerSubject,
    );
    if (existing) return existing;

    const id = crypto.randomUUID();
    const createdAt = Date.now();
    const displayName = profileString(identity.claims, [
      "name",
      "login",
      "username",
    ]) ?? `${identity.provider} user`;
    const avatarUrl = profileUrl(identity.claims, [
      "avatar_url",
      "picture",
      "avatarUrl",
    ]);
    const email =
      identity.email ??
      `${identity.providerSubject}@${identity.provider}.invalid`;

    const claimsJson = JSON.stringify(identity.claims);
    if (
      textEncoder.encode(claimsJson).length >
      MAX_IDENTITY_CLAIMS_LENGTH
    ) {
      throw new TypeError("Identity claims are too large.");
    }

    this.ctx.storage.sql.exec(
      `INSERT INTO users
       (id, email, display_name, avatar_url, provider, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      id,
      email,
      displayName,
      avatarUrl ?? null,
      identity.provider,
      createdAt,
    );
    this.ctx.storage.sql.exec(
      `INSERT INTO identities
       (provider, provider_subject, user_id, email, email_verified, claims_json)
       VALUES (?, ?, ?, ?, ?, ?)`,
      identity.provider,
      identity.providerSubject,
      id,
      identity.email ?? null,
      identity.emailVerified === undefined
        ? null
        : Number(identity.emailVerified),
      claimsJson,
    );

    return {
      id,
      email,
      displayName,
      ...(avatarUrl ? { avatarUrl } : {}),
      provider: identity.provider,
      createdAt: new Date(createdAt),
    };
  }

  findPasswordAccountByEmail(
    email: string,
  ): PasswordAccount<DemoUser> | null {
    const row = first(
      this.ctx.storage.sql.exec<PasswordAccountRow>(
        `SELECT users.*, password_accounts.password_hash,
                password_accounts.email_verified
         FROM password_accounts
         JOIN users ON users.id = password_accounts.user_id
         WHERE password_accounts.email = ?
         LIMIT 1`,
        email,
      ),
    );
    return row ? mapPasswordAccount(row) : null;
  }

  findPasswordAccountByUserId(
    userId: string,
  ): PasswordAccount<DemoUser> | null {
    const row = first(
      this.ctx.storage.sql.exec<PasswordAccountRow>(
        `SELECT users.*, password_accounts.password_hash,
                password_accounts.email_verified
         FROM password_accounts
         JOIN users ON users.id = password_accounts.user_id
         WHERE password_accounts.user_id = ?
         LIMIT 1`,
        userId,
      ),
    );
    return row ? mapPasswordAccount(row) : null;
  }

  createPasswordAccount(input: CreatePasswordAccountInput): DemoUser {
    const id = crypto.randomUUID();
    const createdAt = Date.now();
    const displayName = input.email.slice(0, input.email.indexOf("@"));

    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        `INSERT INTO users
         (id, email, display_name, avatar_url, provider, created_at)
         VALUES (?, ?, ?, NULL, 'password', ?)`,
        id,
        input.email,
        displayName,
        createdAt,
      );
      this.ctx.storage.sql.exec(
        `INSERT INTO password_accounts
         (email, user_id, password_hash, email_verified)
         VALUES (?, ?, ?, ?)`,
        input.email,
        id,
        input.passwordHash,
        Number(input.emailVerified),
      );
    });

    return {
      id,
      email: input.email,
      displayName,
      provider: "password",
      createdAt: new Date(createdAt),
    };
  }

  updatePassword(userId: string, passwordHash: string): void {
    this.ctx.storage.sql.exec(
      "UPDATE password_accounts SET password_hash = ? WHERE user_id = ?",
      passwordHash,
      userId,
    );
  }

  markEmailVerified(userId: string): void {
    this.ctx.storage.sql.exec(
      "UPDATE password_accounts SET email_verified = 1 WHERE user_id = ?",
      userId,
    );
  }

  createChallenge(challenge: StoredChallengeRecord): void {
    this.deleteExpired();
    this.ctx.storage.sql.exec(
      `INSERT INTO auth_challenges
       (token_hash, provider, kind, payload_ciphertext, payload_iv,
        created_at, expires_at, attempts)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      challenge.tokenHash,
      challenge.provider,
      challenge.kind,
      challenge.payload.ciphertext,
      challenge.payload.iv,
      challenge.createdAt.getTime(),
      challenge.expiresAt.getTime(),
      challenge.attempts,
    );
  }

  consumeChallenge(tokenHash: string): StoredChallengeRecord | null {
    this.deleteExpired();
    let record: StoredChallengeRecord | null = null;
    this.ctx.storage.transactionSync(() => {
      const row = first(
        this.ctx.storage.sql.exec<ChallengeRow>(
          "SELECT * FROM auth_challenges WHERE token_hash = ? LIMIT 1",
          tokenHash,
        ),
      );
      if (!row) return;
      this.ctx.storage.sql.exec(
        "DELETE FROM auth_challenges WHERE token_hash = ?",
        tokenHash,
      );
      record = mapChallenge(row);
    });
    return record;
  }

  findChallenge(tokenHash: string): StoredChallengeRecord | null {
    this.deleteExpired();
    const row = first(
      this.ctx.storage.sql.exec<ChallengeRow>(
        "SELECT * FROM auth_challenges WHERE token_hash = ? LIMIT 1",
        tokenHash,
      ),
    );
    return row ? mapChallenge(row) : null;
  }

  incrementChallengeAttempts(
    tokenHash: string,
    expectedAttempts: number,
  ): boolean {
    this.deleteExpired();
    const result = this.ctx.storage.sql.exec(
      `UPDATE auth_challenges
       SET attempts = attempts + 1
       WHERE token_hash = ? AND attempts = ?`,
      tokenHash,
      expectedAttempts,
    );
    return result.rowsWritten === 1;
  }

  saveOtpCredential(credential: StoredOtpCredential): void {
    this.ctx.storage.sql.exec(
      `INSERT INTO otp_credentials
       (user_id, secret_ciphertext, secret_iv, last_accepted_step,
        recovery_code_hashes_json)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         secret_ciphertext = excluded.secret_ciphertext,
         secret_iv = excluded.secret_iv,
         last_accepted_step = excluded.last_accepted_step,
         recovery_code_hashes_json = excluded.recovery_code_hashes_json`,
      credential.userId,
      credential.secret.ciphertext,
      credential.secret.iv,
      credential.lastAcceptedStep,
      JSON.stringify(credential.recoveryCodeHashes),
    );
  }

  findOtpCredential(userId: string): StoredOtpCredential | null {
    const row = first(
      this.ctx.storage.sql.exec<OtpCredentialRow>(
        "SELECT * FROM otp_credentials WHERE user_id = ? LIMIT 1",
        userId,
      ),
    );
    return row ? mapOtpCredential(row) : null;
  }

  advanceOtpStep(userId: string, nextStep: string): boolean {
    if (!/^\d+$/u.test(nextStep)) return false;
    const row = first(
      this.ctx.storage.sql.exec<Pick<OtpCredentialRow, "last_accepted_step">>(
        "SELECT last_accepted_step FROM otp_credentials WHERE user_id = ?",
        userId,
      ),
    );
    if (!row || BigInt(nextStep) <= BigInt(row.last_accepted_step)) {
      return false;
    }
    this.ctx.storage.sql.exec(
      "UPDATE otp_credentials SET last_accepted_step = ? WHERE user_id = ?",
      nextStep,
      userId,
    );
    return true;
  }

  consumeRecoveryCode(userId: string, codeHash: string): boolean {
    let consumed = false;
    this.ctx.storage.transactionSync(() => {
      const credential = this.findOtpCredential(userId);
      if (!credential) return;
      const remaining = credential.recoveryCodeHashes.filter((candidate) => {
        if (!consumed && candidate === codeHash) {
          consumed = true;
          return false;
        }
        return true;
      });
      if (!consumed) return;
      this.ctx.storage.sql.exec(
        `UPDATE otp_credentials
         SET recovery_code_hashes_json = ?
         WHERE user_id = ?`,
        JSON.stringify(remaining),
        userId,
      );
    });
    return consumed;
  }

  hasOtpCredential(userId: string): boolean {
    return Boolean(
      first(
        this.ctx.storage.sql.exec<{ readonly present: number }>(
          `SELECT 1 AS present
           FROM otp_credentials
           WHERE user_id = ?
           LIMIT 1`,
          userId,
        ),
      ),
    );
  }

  saveWebAuthnCredential(credential: WebAuthnCredential): void {
    const existing = this.findWebAuthnCredential(credential.id);
    if (existing && existing.userId !== credential.userId) {
      throw new TypeError("A passkey cannot be reassigned to another user.");
    }
    if (
      !existing &&
      this.countWebAuthnCredentials(credential.userId) >=
        MAX_WEBAUTHN_CREDENTIALS_PER_USER
    ) {
      throw new TypeError("Too many passkeys are registered for this user.");
    }
    const publicKeyJwkJson = JSON.stringify(credential.publicKeyJwk);
    const transportsJson = credential.transports
      ? JSON.stringify(credential.transports)
      : null;
    if (
      textEncoder.encode(publicKeyJwkJson).byteLength >
        MAX_WEBAUTHN_JSON_LENGTH ||
      (transportsJson &&
        textEncoder.encode(transportsJson).byteLength >
          MAX_WEBAUTHN_JSON_LENGTH)
    ) {
      throw new TypeError("Passkey data is too large.");
    }
    this.ctx.storage.sql.exec(
      `INSERT INTO webauthn_credentials
       (id, user_id, public_key_jwk_json, algorithm, sign_count,
        transports_json, backup_eligible, backed_up, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         public_key_jwk_json = excluded.public_key_jwk_json,
         algorithm = excluded.algorithm,
         sign_count = excluded.sign_count,
         transports_json = excluded.transports_json,
         backup_eligible = excluded.backup_eligible,
         backed_up = excluded.backed_up,
         updated_at = excluded.updated_at`,
      credential.id,
      credential.userId,
      publicKeyJwkJson,
      credential.algorithm,
      credential.signCount,
      transportsJson,
      Number(credential.backupEligible),
      Number(credential.backedUp),
      credential.createdAt.getTime(),
      credential.updatedAt.getTime(),
    );
  }

  findWebAuthnCredential(
    credentialId: string,
  ): WebAuthnCredential | null {
    const row = first(
      this.ctx.storage.sql.exec<WebAuthnCredentialRow>(
        "SELECT * FROM webauthn_credentials WHERE id = ? LIMIT 1",
        credentialId,
      ),
    );
    return row ? mapWebAuthnCredential(row) : null;
  }

  listWebAuthnCredentials(
    userId: string,
  ): readonly WebAuthnCredential[] {
    return [
      ...this.ctx.storage.sql.exec<WebAuthnCredentialRow>(
        `SELECT *
         FROM webauthn_credentials
         WHERE user_id = ?
         ORDER BY created_at`,
        userId,
      ),
    ].map(mapWebAuthnCredential);
  }

  countWebAuthnCredentials(userId: string): number {
    const row = first(
      this.ctx.storage.sql.exec<{ readonly total: number }>(
        `SELECT COUNT(*) AS total
         FROM webauthn_credentials
         WHERE user_id = ?`,
        userId,
      ),
    );
    return row?.total ?? 0;
  }

  updateWebAuthnSignCount(input: {
    readonly credentialId: string;
    readonly previousSignCount: number;
    readonly signCount: number;
    readonly backedUp: boolean;
    readonly updatedAt: Date;
  }): boolean {
    const result = this.ctx.storage.sql.exec(
      `UPDATE webauthn_credentials
       SET sign_count = ?, backed_up = ?, updated_at = ?
       WHERE id = ? AND sign_count = ?`,
      input.signCount,
      Number(input.backedUp),
      input.updatedAt.getTime(),
      input.credentialId,
      input.previousSignCount,
    );
    return result.rowsWritten === 1;
  }

  createSession(session: AuthSessionRecord): void {
    this.ctx.storage.sql.exec(
      `INSERT INTO sessions
       (token_hash, user_id, created_at, expires_at)
       VALUES (?, ?, ?, ?)`,
      session.tokenHash,
      session.userId,
      session.createdAt.getTime(),
      session.expiresAt.getTime(),
    );
  }

  findSession(tokenHash: string): AuthSessionRecord | null {
    this.deleteExpired();
    const row = first(
      this.ctx.storage.sql.exec<SessionRow>(
        "SELECT * FROM sessions WHERE token_hash = ? LIMIT 1",
        tokenHash,
      ),
    );
    return row
      ? {
          tokenHash: row.token_hash,
          userId: row.user_id,
          createdAt: new Date(row.created_at),
          expiresAt: new Date(row.expires_at),
        }
      : null;
  }

  deleteSession(tokenHash: string): void {
    this.ctx.storage.sql.exec(
      "DELETE FROM sessions WHERE token_hash = ?",
      tokenHash,
    );
  }

  createOAuthState(state: OAuthStateRecord): void {
    this.deleteExpired();
    this.ctx.storage.sql.exec(
      `INSERT INTO oauth_states
       (state_hash, provider, code_verifier, nonce, redirect_uri, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      state.stateHash,
      state.provider,
      state.codeVerifier ?? null,
      state.nonce ?? null,
      state.redirectUri ?? null,
      state.createdAt.getTime(),
      state.expiresAt.getTime(),
    );
  }

  consumeOAuthState(stateHash: string): OAuthStateRecord | null {
    this.deleteExpired();
    const row = first(
      this.ctx.storage.sql.exec<StateRow>(
        "SELECT * FROM oauth_states WHERE state_hash = ? LIMIT 1",
        stateHash,
      ),
    );
    if (!row) return null;
    this.ctx.storage.sql.exec(
      "DELETE FROM oauth_states WHERE state_hash = ?",
      stateHash,
    );
    return {
      stateHash: row.state_hash,
      provider: row.provider,
      ...(row.code_verifier ? { codeVerifier: row.code_verifier } : {}),
      ...(row.nonce ? { nonce: row.nonce } : {}),
      ...(row.redirect_uri ? { redirectUri: row.redirect_uri } : {}),
      createdAt: new Date(row.created_at),
      expiresAt: new Date(row.expires_at),
    };
  }

  private deleteExpired(): void {
    const now = Date.now();
    if (now < this.#nextCleanupAt) return;
    this.#nextCleanupAt = now + CLEANUP_INTERVAL_MS;
    this.ctx.storage.sql.exec(
      "DELETE FROM sessions WHERE expires_at <= ?",
      now,
    );
    this.ctx.storage.sql.exec(
      "DELETE FROM oauth_states WHERE expires_at <= ?",
      now,
    );
    this.ctx.storage.sql.exec(
      "DELETE FROM auth_challenges WHERE expires_at <= ?",
      now,
    );
  }
}

function first<Row>(cursor: Iterable<Row>): Row | undefined {
  for (const row of cursor) return row;
  return undefined;
}

function mapUser(row: UserRow): DemoUser {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    ...(row.avatar_url ? { avatarUrl: row.avatar_url } : {}),
    provider: row.provider,
    createdAt: new Date(row.created_at),
  };
}

function mapPasswordAccount(
  row: PasswordAccountRow,
): PasswordAccount<DemoUser> {
  return {
    user: mapUser(row),
    passwordHash: row.password_hash,
    emailVerified: row.email_verified === 1,
  };
}

function mapChallenge(row: ChallengeRow): StoredChallengeRecord {
  if (!isAuthChallengeKind(row.kind)) {
    throw new TypeError("Stored authentication challenge is invalid.");
  }
  return {
    tokenHash: row.token_hash,
    provider: row.provider,
    kind: row.kind,
    payload: {
      ciphertext: row.payload_ciphertext,
      iv: row.payload_iv,
    },
    createdAt: new Date(row.created_at),
    expiresAt: new Date(row.expires_at),
    attempts: row.attempts,
  };
}

function mapOtpCredential(row: OtpCredentialRow): StoredOtpCredential {
  const recoveryCodeHashes: unknown = JSON.parse(
    row.recovery_code_hashes_json,
  );
  if (
    !Array.isArray(recoveryCodeHashes) ||
    recoveryCodeHashes.some((value) => typeof value !== "string")
  ) {
    throw new TypeError("Stored OTP recovery codes are invalid.");
  }
  return {
    userId: row.user_id,
    secret: {
      ciphertext: row.secret_ciphertext,
      iv: row.secret_iv,
    },
    lastAcceptedStep: row.last_accepted_step,
    recoveryCodeHashes,
  };
}

function mapWebAuthnCredential(
  row: WebAuthnCredentialRow,
): WebAuthnCredential {
  const publicKeyJwk: unknown = JSON.parse(row.public_key_jwk_json);
  const transports: unknown = row.transports_json
    ? JSON.parse(row.transports_json)
    : undefined;
  if (
    !isJsonWebKey(publicKeyJwk) ||
    (row.algorithm !== "ES256" && row.algorithm !== "RS256") ||
    (transports !== undefined && !isAuthenticatorTransports(transports))
  ) {
    throw new TypeError("Stored passkey data is invalid.");
  }
  return {
    id: row.id,
    userId: row.user_id,
    publicKeyJwk,
    algorithm: row.algorithm,
    signCount: row.sign_count,
    ...(transports ? { transports } : {}),
    backupEligible: row.backup_eligible === 1,
    backedUp: row.backed_up === 1,
    createdAt: new Date(row.created_at),
    updatedAt: new Date(row.updated_at),
  };
}

function isAuthChallengeKind(value: string): value is AuthChallengeKind {
  return [
    "custom",
    "email_otp",
    "email_verification",
    "mfa_selection",
    "mfa_setup",
    "new_password",
    "password",
    "password_reset",
    "sms_mfa",
    "sms_otp",
    "software_token_mfa",
    "unsupported",
    "webauthn",
  ].includes(value);
}

function isAuthenticatorTransports(
  value: unknown,
): value is readonly AuthenticatorTransport[] {
  return (
    Array.isArray(value) &&
    value.every(
      (transport) =>
        transport === "ble" ||
        transport === "hybrid" ||
        transport === "internal" ||
        transport === "nfc" ||
        transport === "usb",
    )
  );
}

function isJsonWebKey(value: unknown): value is JsonWebKey {
  return (
    isRecord(value) &&
    typeof value.kty === "string" &&
    value.kty.length > 0
  );
}


function profileString(
  claims: Readonly<Record<string, unknown>>,
  keys: readonly string[],
): string | undefined {
  for (const key of keys) {
    const value = claims[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

function profileUrl(
  claims: Readonly<Record<string, unknown>>,
  keys: readonly string[],
): string | undefined {
  const value = profileString(claims, keys);
  if (!value || value.length > 2_048) return undefined;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password
      ? url.href
      : undefined;
  } catch {
    return undefined;
  }
}
