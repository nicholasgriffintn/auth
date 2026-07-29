import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { AuthError, createAuth, type AuthUser } from "@ngriffin_uk/auth-core";

import {
  passwordAuth,
  type PasswordAccount,
  type PasswordPolicy,
} from "./index.js";

interface TestUser extends AuthUser {
  readonly role: string;
}

function setup(
  existing?: PasswordAccount<TestUser>,
  capabilities: {
    readonly emailVerification?: boolean;
    readonly passwordReset?: boolean;
    readonly policy?: PasswordPolicy;
  } = {}
) {
  const now = new Date("2026-01-01T00:00:00.000Z");
  const users = new Map<string, TestUser>();
  if (existing) {
    users.set(existing.user.id, existing.user);
  }
  const hashCalls: string[] = [];
  const hasher = {
    async hash(password: string) {
      hashCalls.push(password);
      return `hashed:${password}`;
    },
    async verify(password: string, hash: string) {
      return hash === `hashed:${password}`;
    },
  };
  const sessions = new Map<string, { userId: string }>();
  const challenges = new Map<
    string,
    import("@ngriffin_uk/auth-core").AuthChallengeRecord
  >();
  const deliveries: Array<{ token: string; userId: string }> = [];
  const passwordUpdates: Array<{ userId: string; passwordHash: string }> = [];
  const verifiedUsers: string[] = [];
  const createCalls: Array<{
    email: string;
    passwordHash: string;
    emailVerified: boolean;
  }> = [];
  let findCalls = 0;
  const store = {
    async findByEmail(email: string) {
      findCalls += 1;
      return existing?.user.email === email ? existing : null;
    },
    async findByUserId(userId: string) {
      return existing?.user.id === userId ? existing : null;
    },
    async create(input: {
      email: string;
      passwordHash: string;
      emailVerified: boolean;
    }) {
      createCalls.push(input);
      const user: TestUser = {
        id: "new-user",
        email: input.email,
        createdAt: now,
        role: "member",
      };
      users.set(user.id, user);
      return user;
    },
    async updatePassword(userId: string, passwordHash: string) {
      passwordUpdates.push({ userId, passwordHash });
    },
    async markEmailVerified(userId: string) {
      verifiedUsers.push(userId);
    },
  };
  const auth = createAuth<TestUser>({
    users: {
      async findById(userId) {
        return users.get(userId) ?? null;
      },
    },
    sessions: {
      async create(session) {
        sessions.set(session.tokenHash, { userId: session.userId });
      },
      async findByTokenHash() {
        return null;
      },
      async deleteByTokenHash() {},
    },
    challenges: {
      async create(record) {
        challenges.set(record.tokenHash, record);
      },
      async consumeByTokenHash(tokenHash) {
        const record = challenges.get(tokenHash) ?? null;
        challenges.delete(tokenHash);
        return record;
      },
    },
    clock: () => now,
    randomBytes: (length) => new Uint8Array(length).fill(3),
  }).use(
    passwordAuth({
      store,
      hasher,
      ...(capabilities.policy ? { policy: capabilities.policy } : {}),
      ...(capabilities.emailVerification
        ? {
            emailVerification: {
              async send(delivery) {
                deliveries.push({
                  token: delivery.token,
                  userId: delivery.user.id,
                });
              },
            },
          }
        : {}),
      ...(capabilities.passwordReset
        ? {
            passwordReset: {
              async send(delivery) {
                deliveries.push({
                  token: delivery.token,
                  userId: delivery.user.id,
                });
              },
            },
          }
        : {}),
    })
  );

  return {
    auth,
    hashCalls,
    createCalls,
    deliveries,
    passwordUpdates,
    verifiedUsers,
    getFindCalls: () => findCalls,
  };
}

describe("passwordAuth", () => {
  it("normalises the email and delegates account creation", async () => {
    const { auth, createCalls } = setup();

    const result = await auth.providers.password.signUp({
      email: " Person@Example.COM ",
      password: "long enough password",
    });

    assert.equal(result.status, "authenticated");
    if (result.status !== "authenticated") {
      throw new Error("Expected an authenticated result.");
    }
    assert.equal(result.session.user.email, "person@example.com");
    assert.deepEqual(createCalls, [
      {
        email: "person@example.com",
        passwordHash: "hashed:long enough password",
        emailVerified: true,
      },
    ]);
    assert.ok(result.session.token);
  });

  it("returns one safe error for missing users and bad passwords", async () => {
    const user: TestUser = {
      id: "user-1",
      email: "person@example.com",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      role: "member",
    };
    const missing = setup();
    const incorrect = setup({
      user,
      passwordHash: "hashed:correct password",
      emailVerified: true,
    });

    const attempts = [
      missing.auth.providers.password.signIn({
        email: user.email,
        password: "incorrect password",
      }),
      incorrect.auth.providers.password.signIn({
        email: user.email,
        password: "incorrect password",
      }),
    ];

    for (const attempt of attempts) {
      await assert.rejects(
        attempt,
        (error) =>
          error instanceof AuthError && error.code === "invalid_credentials"
      );
    }
    assert.deepEqual(missing.hashCalls, ["incorrect password"]);
  });

  it("verifies credentials without issuing a session", async () => {
    const user: TestUser = {
      id: "user-1",
      email: "person@example.com",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      role: "member",
    };
    const setupResult = setup({
      user,
      passwordHash: "hashed:correct password",
      emailVerified: true,
    });

    assert.deepEqual(
      await setupResult.auth.providers.password.verifyCredentials({
        email: user.email,
        password: "correct password",
      }),
      user
    );
    assert.equal(
      await setupResult.auth.validateSession("not-a-session"),
      null
    );
  });

  it("allows existing credentials that predate a stricter creation policy", async () => {
    const user: TestUser = {
      id: "user-1",
      email: "person@example.com",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      role: "member",
    };
    const setupResult = setup(
      {
        user,
        passwordHash: "hashed:legacy-password",
        emailVerified: true,
      },
      {
        policy: {
          validate(password) {
            return password.length >= 30 ? null : "Use at least 30 characters.";
          },
        },
      }
    );

    const result = await setupResult.auth.providers.password.signIn({
      email: user.email,
      password: "legacy-password",
    });
    assert.equal(result.status, "authenticated");

    await assert.rejects(
      setupResult.auth.providers.password.signUp({
        email: "new@example.com",
        password: "legacy-password",
      }),
      (error) => error instanceof AuthError && error.code === "invalid_input"
    );
  });

  it("rejects weak passwords before touching storage", async () => {
    const { auth, getFindCalls } = setup();

    await assert.rejects(
      auth.providers.password.signUp({
        email: "person@example.com",
        password: "short",
      }),
      (error) => error instanceof AuthError && error.code === "invalid_input"
    );
    assert.equal(getFindCalls(), 0);
  });

  it("uses opaque challenges for email verification", async () => {
    const setupResult = setup(undefined, { emailVerification: true });
    const signUpResult =
      await setupResult.auth.providers.password.signUp({
        email: "person@example.com",
        password: "long enough password",
      });
    assert.equal(signUpResult.status, "email_verification_required");
    assert.equal(setupResult.deliveries.length, 1);
    const delivery = setupResult.deliveries[0];
    assert.ok(delivery);

    const verified =
      await setupResult.auth.providers.password.verifyEmail({
        token: delivery.token,
      });
    assert.equal(verified.status, "authenticated");
    assert.deepEqual(setupResult.verifiedUsers, ["new-user"]);
  });

  it("resets passwords without exposing whether an email exists", async () => {
    const user: TestUser = {
      id: "user-1",
      email: "person@example.com",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      role: "member",
    };
    const setupResult = setup(
      {
        user,
        passwordHash: "hashed:old password",
        emailVerified: true,
      },
      { passwordReset: true }
    );
    await setupResult.auth.providers.password.requestPasswordReset(user.email);
    const delivery = setupResult.deliveries[0];
    assert.ok(delivery);
    await setupResult.auth.providers.password.resetPassword({
      token: delivery.token,
      newPassword: "a new long password",
    });
    assert.deepEqual(setupResult.passwordUpdates, [
      {
        userId: user.id,
        passwordHash: "hashed:a new long password",
      },
    ]);

    await setupResult.auth.providers.password.requestPasswordReset(
      "missing@example.com"
    );
    assert.equal(setupResult.deliveries.length, 1);
  });
});
