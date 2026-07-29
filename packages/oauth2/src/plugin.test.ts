import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  AuthError,
  createAuth,
  type AuthSessionRecord,
  type AuthUser,
} from "@ngriffin_uk/auth-core";

import {
  oauth2Auth,
  type OidcConfig,
  type OAuthStateRecord,
  type OAuthStateStore,
  type OAuthTokenSet,
} from "./index.js";
import { signJwt } from "@ngriffin_uk/auth-jwt";

interface TestUser extends AuthUser {
  readonly role: string;
}

interface SetupOptions {
  readonly clientAuthentication?: "basic" | "body" | "none";
  readonly clientIdParameter?: string;
  readonly pkce?: boolean;
  readonly clientId?: string;
  readonly clientSecret?: string;
  readonly oidc?: OidcConfig;
  readonly responseBody?: unknown | (() => unknown | Promise<unknown>);
  readonly scopeSeparator?: " " | ",";
  readonly scopes?: readonly string[];
  readonly tokenParameters?: {
    readonly authorization_code?: Readonly<Record<string, string>>;
  };
  readonly tokenResponsePath?: readonly string[];
}

function setup(options: SetupOptions = {}) {
  const now = new Date("2026-01-01T00:00:00.000Z");
  const user: TestUser = {
    id: "user-1",
    email: "person@example.com",
    createdAt: now,
    role: "member",
  };
  const states = new Map<string, OAuthStateRecord>();
  const stateStore: OAuthStateStore = {
    async create(record) {
      states.set(record.stateHash, record);
    },
    async consumeByStateHash(stateHash) {
      const record = states.get(stateHash) ?? null;
      states.delete(stateHash);
      return record;
    },
  };
  const sessions = new Map<string, AuthSessionRecord>();
  let tokenRequestBody = "";
  let tokenRequestInit: RequestInit | undefined;
  let resolvedTokens: OAuthTokenSet | undefined;
  const request: typeof fetch = async (_input, init) => {
    tokenRequestBody = String(init?.body);
    tokenRequestInit = init;
    return new Response(
      JSON.stringify(
        typeof options.responseBody === "function"
          ? await options.responseBody()
          : options.responseBody ?? {
              access_token: "access-token",
              token_type: "Bearer",
              expires_in: 3600,
              scope: "openid email",
            }
      ),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }
    );
  };

  const auth = createAuth<TestUser>({
    users: {
      async findById(userId) {
        return userId === user.id ? user : null;
      },
    },
    identities: {
      async findUser() {
        return user;
      },
      async resolve(identity) {
        assert.equal(identity.providerSubject, "external-1");
        return user;
      },
    },
    sessions: {
      async create(session) {
        sessions.set(session.tokenHash, session);
      },
      async findByTokenHash(tokenHash) {
        return sessions.get(tokenHash) ?? null;
      },
      async deleteByTokenHash(tokenHash) {
        sessions.delete(tokenHash);
      },
    },
    clock: () => now,
    randomBytes: (length) => new Uint8Array(length).fill(11),
  }).use(
    oauth2Auth({
      name: "github",
      clientId: options.clientId ?? "client-id",
      clientSecret: options.clientSecret ?? "client-secret",
      redirectUri: "https://app.example/callback",
      authorizationEndpoint: "https://github.example/authorize",
      tokenEndpoint: "https://github.example/token",
      scopes: options.scopes ?? ["read:user"],
      ...(options.clientAuthentication
        ? { clientAuthentication: options.clientAuthentication }
        : {}),
      ...(options.clientIdParameter
        ? { clientIdParameter: options.clientIdParameter }
        : {}),
      ...(options.pkce === undefined ? {} : { pkce: options.pkce }),
      ...(options.scopeSeparator
        ? { scopeSeparator: options.scopeSeparator }
        : {}),
      ...(options.tokenParameters
        ? { tokenParameters: options.tokenParameters }
        : {}),
      ...(options.tokenResponsePath
        ? { tokenResponsePath: options.tokenResponsePath }
        : {}),
      stateStore,
      fetch: request,
      ...(options.oidc ? { oidc: options.oidc } : {}),
      async resolveIdentity(tokens) {
        resolvedTokens = tokens;
        return {
          provider: "github",
          providerSubject: "external-1",
          email: "person@example.com",
          claims: {},
        };
      },
    })
  );
  return {
    auth,
    states,
    getTokenRequestBody: () => tokenRequestBody,
    getTokenRequestInit: () => tokenRequestInit,
    getResolvedTokens: () => resolvedTokens,
  };
}

describe("oauth2Auth", () => {
  it("persists hashed state, adds PKCE, and completes a session", async () => {
    const setupResult = setup();
    const url = await setupResult.auth.providers.github.startAuthorization();
    const state = url.searchParams.get("state");

    assert.ok(state);
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.ok(url.searchParams.get("code_challenge"));
    assert.equal(url.searchParams.get("scope"), "read:user");
    assert.equal([...setupResult.states.values()][0]?.stateHash === state, false);

    const result =
      await setupResult.auth.providers.github.completeAuthorization({
        code: "authorization-code",
        state,
      });
    assert.equal(result.status, "authenticated");
    assert.match(
      setupResult.getTokenRequestBody(),
      /code_verifier=/u
    );
    assert.equal(setupResult.getTokenRequestInit()?.redirect, "error");
    assert.equal(
      setupResult.getResolvedTokens()?.expiresAt?.toISOString(),
      "2026-01-01T01:00:00.000Z"
    );
  });

  it("consumes state once", async () => {
    const setupResult = setup();
    const url = await setupResult.auth.providers.github.startAuthorization();
    const state = url.searchParams.get("state");
    assert.ok(state);
    await setupResult.auth.providers.github.completeAuthorization({
      code: "authorization-code",
      state,
    });

    await assert.rejects(
      setupResult.auth.providers.github.completeAuthorization({
        code: "authorization-code",
        state,
      }),
      (error) => error instanceof AuthError && error.code === "invalid_callback"
    );
  });

  it("supports provider-specific public parameters and response envelopes", async () => {
    const setupResult = setup({
      clientAuthentication: "body",
      clientIdParameter: "client_key",
      pkce: false,
      scopeSeparator: ",",
      scopes: ["profile", "email"],
      tokenParameters: {
        authorization_code: { action: "requesttoken" },
      },
      tokenResponsePath: ["body"],
      responseBody: {
        body: {
          access_token: "access-token",
          token_type: "Bearer",
        },
      },
    });
    const url = await setupResult.auth.providers.github.startAuthorization();
    const state = url.searchParams.get("state");
    assert.ok(state);

    assert.equal(url.searchParams.get("client_key"), "client-id");
    assert.equal(url.searchParams.get("scope"), "profile,email");
    assert.equal(url.searchParams.has("code_challenge"), false);

    await setupResult.auth.providers.github.completeAuthorization({
      code: "authorization-code",
      state,
    });
    const body = new URLSearchParams(setupResult.getTokenRequestBody());
    assert.equal(body.get("client_key"), "client-id");
    assert.equal(body.get("client_secret"), "client-secret");
    assert.equal(body.get("action"), "requesttoken");
    assert.equal(body.has("code_verifier"), false);
  });

  it("rejects credential-bearing provider endpoints", () => {
    assert.throws(
      () =>
        oauth2Auth({
          name: "invalid",
          clientId: "client-id",
          authorizationEndpoint: "https://user@example.com/authorize",
          tokenEndpoint: "https://example.com/token",
          stateStore: {
            async create() {},
            async consumeByStateHash() {
              return null;
            },
          },
          async resolveIdentity() {
            throw new Error("not reached");
          },
        }),
      (error) =>
        error instanceof AuthError && error.code === "invalid_input"
    );
  });

  it("rejects oversized callback and token inputs before requests", async () => {
    const setupResult = setup();
    await assert.rejects(
      setupResult.auth.providers.github.completeAuthorization({
        code: "code",
        state: "x".repeat(4_097),
      }),
      (error) =>
        error instanceof AuthError && error.code === "invalid_callback"
    );
    assert.throws(
      () => setupResult.auth.providers.github.refresh(""),
      (error) =>
        error instanceof AuthError && error.code === "invalid_input"
    );
  });

  it("uses form encoding for HTTP Basic client credentials", async () => {
    const setupResult = setup({
      clientId: "client id",
      clientSecret: "s:e!",
    });
    const url = await setupResult.auth.providers.github.startAuthorization();
    const state = url.searchParams.get("state");
    assert.ok(state);

    await setupResult.auth.providers.github.completeAuthorization({
      code: "authorization-code",
      state,
    });

    assert.equal(
      new Headers(setupResult.getTokenRequestInit()?.headers).get(
        "Authorization"
      ),
      `Basic ${Buffer.from("client+id:s%3Ae%21").toString("base64")}`
    );
  });

  it("does not persist state when authorization options are invalid", async () => {
    const setupResult = setup();

    await assert.rejects(
      setupResult.auth.providers.github.startAuthorization({
        authorizationParameters: { state: "attacker-controlled" },
      }),
      (error) =>
        error instanceof AuthError && error.code === "invalid_input"
    );
    assert.equal(setupResult.states.size, 0);
  });

  it("requires OIDC claims and azp for multiple audiences", async () => {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode("a sufficiently long test secret"),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
    let idToken = "";
    const setupResult = setup({
      oidc: {
        issuer: "https://issuer.example",
        algorithms: ["HS256"],
        key,
      },
      responseBody: () => ({
        access_token: "access-token",
        token_type: "Bearer",
        id_token: idToken,
      }),
    });
    const url = await setupResult.auth.providers.github.startAuthorization();
    const state = url.searchParams.get("state");
    const nonce = [...setupResult.states.values()][0]?.nonce;
    assert.ok(state && nonce);

    idToken = await signJwt(
      {
        iss: "https://issuer.example",
        aud: ["client-id", "another-client"],
        sub: "external-1",
        exp: 1_767_225_900,
        iat: 1_767_225_600,
        nonce,
      },
      { algorithm: "HS256", key }
    );

    await assert.rejects(
      setupResult.auth.providers.github.completeAuthorization({
        code: "authorization-code",
        state,
      }),
      (error) =>
        error instanceof AuthError && error.code === "invalid_callback"
    );

    const validUrl =
      await setupResult.auth.providers.github.startAuthorization();
    const validState = validUrl.searchParams.get("state");
    const validNonce = [...setupResult.states.values()][0]?.nonce;
    assert.ok(validState && validNonce);
    idToken = await signJwt(
      {
        iss: "https://issuer.example",
        aud: ["client-id", "another-client"],
        azp: "client-id",
        sub: "external-1",
        exp: 1_767_225_900,
        iat: 1_767_225_600,
        nonce: validNonce,
      },
      { algorithm: "HS256", key }
    );
    assert.equal(
      (
        await setupResult.auth.providers.github.completeAuthorization({
          code: "authorization-code",
          state: validState,
        })
      ).status,
      "authenticated"
    );
  });
});
