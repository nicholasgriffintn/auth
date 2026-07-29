import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { AuthError, createAuth, hashSecret } from "./index.js";
import type {
  AuthSessionRecord,
  AuthUser,
  SessionStore,
} from "./index.js";

interface TestUser extends AuthUser {
  readonly displayName: string;
}

function createStores(user: TestUser) {
  const sessions = new Map<string, AuthSessionRecord>();
  const challenges = new Map<
    string,
    import("./index.js").AuthChallengeRecord
  >();
  const sessionStore: SessionStore = {
    async create(session) {
      sessions.set(session.tokenHash, session);
    },
    async findByTokenHash(tokenHash) {
      return sessions.get(tokenHash) ?? null;
    },
    async deleteByTokenHash(tokenHash) {
      sessions.delete(tokenHash);
    },
  };
  return {
    sessions,
    challenges,
    challengeStore: {
      async create(record: import("./index.js").AuthChallengeRecord) {
        challenges.set(record.tokenHash, record);
      },
      async consumeByTokenHash(tokenHash: string) {
        const record = challenges.get(tokenHash) ?? null;
        challenges.delete(tokenHash);
        return record;
      },
    },
    sessionStore,
    users: {
      async findById(userId: string) {
        return userId === user.id ? user : null;
      },
    },
  };
}

describe("createAuth", () => {
  it("stores only a hash and validates the raw token", async () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const user: TestUser = {
      id: "user-1",
      email: "person@example.com",
      createdAt: now,
      displayName: "Person",
    };
    const stores = createStores(user);
    const auth = createAuth({
      users: stores.users,
      sessions: stores.sessionStore,
      clock: () => now,
      randomBytes: (length) => new Uint8Array(length).fill(7),
    });

    const issued = await auth.createSession(user.id);
    const stored = [...stores.sessions.values()][0];

    assert.equal(stored?.tokenHash, await hashSecret(issued.token));
    assert.notEqual(stored?.tokenHash, issued.token);
    assert.deepEqual(await auth.validateSession(issued.token), user);
  });

  it("authenticates with one session lookup", async () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const user: TestUser = {
      id: "user-1",
      email: "person@example.com",
      createdAt: now,
      displayName: "Person",
    };
    const stores = createStores(user);
    let lookups = 0;
    const auth = createAuth({
      users: stores.users,
      sessions: {
        ...stores.sessionStore,
        async findByTokenHash(tokenHash) {
          lookups += 1;
          return stores.sessionStore.findByTokenHash(tokenHash);
        },
      },
      clock: () => now,
      randomBytes: (length) => new Uint8Array(length).fill(12),
    });
    const issued = await auth.createSession(user.id);

    assert.equal((await auth.authenticate(issued.token))?.user.id, user.id);
    assert.equal(lookups, 1);
  });

  it("rejects invalid random-source output before storage", async () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const user: TestUser = {
      id: "user-1",
      email: "person@example.com",
      createdAt: now,
      displayName: "Person",
    };
    const stores = createStores(user);
    const auth = createAuth({
      users: stores.users,
      sessions: stores.sessionStore,
      randomBytes: () => new Uint8Array(1),
    });

    await assert.rejects(
      auth.createSession(user.id),
      (error) =>
        error instanceof AuthError && error.code === "insecure_runtime"
    );
    assert.equal(stores.sessions.size, 0);
  });

  it("rejects invalid clock output before storage", async () => {
    const user: TestUser = {
      id: "user-1",
      email: "person@example.com",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      displayName: "Person",
    };
    const stores = createStores(user);
    const auth = createAuth({
      users: stores.users,
      sessions: stores.sessionStore,
      clock: () => new Date(Number.NaN),
    });

    await assert.rejects(
      auth.createSession(user.id),
      (error) =>
        error instanceof AuthError && error.code === "invalid_input"
    );
    assert.equal(stores.sessions.size, 0);
  });

  it("deletes expired sessions and rejects them", async () => {
    let now = new Date("2026-01-01T00:00:00.000Z");
    const user: TestUser = {
      id: "user-1",
      email: "person@example.com",
      createdAt: now,
      displayName: "Person",
    };
    const stores = createStores(user);
    const auth = createAuth({
      users: stores.users,
      sessions: stores.sessionStore,
      sessionTtlMs: 1_000,
      clock: () => now,
      randomBytes: (length) => new Uint8Array(length).fill(8),
    });
    const issued = await auth.createSession(user.id);

    now = new Date("2026-01-01T00:00:01.000Z");

    assert.equal(await auth.validateSession(issued.token), null);
    assert.equal(stores.sessions.size, 0);
  });

  it("does not let telemetry failures affect authentication", async () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const user: TestUser = {
      id: "user-1",
      email: "person@example.com",
      createdAt: now,
      displayName: "Person",
    };
    const stores = createStores(user);
    const auth = createAuth({
      users: stores.users,
      sessions: stores.sessionStore,
      clock: () => now,
      randomBytes: (length) => new Uint8Array(length).fill(9),
      onEvent: () => {
        throw new Error("telemetry unavailable");
      },
    });

    assert.ok((await auth.createSession(user.id)).token);
  });

  it("rejects duplicate provider names", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const user: TestUser = {
      id: "user-1",
      email: "person@example.com",
      createdAt: now,
      displayName: "Person",
    };
    const stores = createStores(user);
    const plugin = {
      name: "test" as const,
      install: () => ({ run: () => undefined }),
    };
    const auth = createAuth({
      users: stores.users,
      sessions: stores.sessionStore,
    }).use(plugin);

    assert.throws(
      () => auth.use(plugin),
      (error) =>
        error instanceof AuthError && error.code === "duplicate_plugin"
    );
  });

  it("consumes challenge continuations once and binds them to a provider", async () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const user: TestUser = {
      id: "user-1",
      email: "person@example.com",
      createdAt: now,
      displayName: "Person",
    };
    const stores = createStores(user);
    const auth = createAuth({
      users: stores.users,
      sessions: stores.sessionStore,
      challenges: stores.challengeStore,
      clock: () => now,
      randomBytes: (length) => new Uint8Array(length).fill(10),
    });
    const issued = await auth.issueChallenge(
      "cognito",
      "software_token_mfa",
      { upstreamSession: "encrypted-by-store" }
    );

    const challenge = await auth.consumeChallenge(
      issued.token,
      "cognito",
      ["software_token_mfa"]
    );
    assert.equal(challenge.provider, "cognito");
    await assert.rejects(
      auth.consumeChallenge(issued.token, "cognito"),
      (error) =>
        error instanceof AuthError && error.code === "challenge_expired"
    );
  });
});
