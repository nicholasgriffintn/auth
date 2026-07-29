import { DurableObject } from "cloudflare:workers";
import type {
  AuthSessionRecord,
  ExternalIdentity,
} from "@ngriffin_uk/auth-core";
import type { OAuthStateRecord } from "@ngriffin_uk/auth-oauth2";

import type { DemoUser, Env } from "./types";

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

interface StateRow extends Record<string, SqlStorageValue> {
  readonly state_hash: string;
  readonly provider: string;
  readonly code_verifier: string | null;
  readonly nonce: string | null;
  readonly redirect_uri: string | null;
  readonly created_at: number;
  readonly expires_at: number;
}

const schema = `
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
    const avatarUrl = profileString(identity.claims, [
      "avatar_url",
      "picture",
      "avatarUrl",
    ]);
    const email =
      identity.email ??
      `${identity.providerSubject}@${identity.provider}.invalid`;

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
      JSON.stringify(identity.claims),
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
    this.ctx.storage.sql.exec(
      "DELETE FROM sessions WHERE expires_at <= ?",
      now,
    );
    this.ctx.storage.sql.exec(
      "DELETE FROM oauth_states WHERE expires_at <= ?",
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
