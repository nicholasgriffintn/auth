import assert from "node:assert/strict";
import { test } from "node:test";

import { AuthError } from "@ngriffin_uk/auth-core";

import { resolveProviderIdentity } from "../worker/provider-profiles.ts";

const tokens = {
  accessToken: "access-token",
  tokenType: "Bearer",
  values: {},
} as const;

test("GitHub identity resolution selects a verified email and minimises claims", async () => {
  const responses = [
    Response.json({
      id: 42,
      login: "octocat",
      name: "The Octocat",
      email: null,
      avatar_url: "https://avatars.githubusercontent.com/u/42",
      private_field: "do not persist",
    }),
    Response.json([
      {
        email: "octocat@example.com",
        primary: true,
        verified: true,
      },
    ]),
  ];
  const request: typeof fetch = async () => {
    const response = responses.shift();
    assert.ok(response);
    return response;
  };

  const identity = await resolveProviderIdentity("github", tokens, request);
  assert.equal(identity.providerSubject, "42");
  assert.equal(identity.email, "octocat@example.com");
  assert.equal(identity.emailVerified, true);
  assert.deepEqual(identity.claims, {
    id: 42,
    login: "octocat",
    name: "The Octocat",
    avatar_url: "https://avatars.githubusercontent.com/u/42",
  });
});

test("Google identity resolution rejects a response without a subject", async () => {
  const request: typeof fetch = async () =>
    Response.json({ email: "person@example.com" });

  await assert.rejects(
    resolveProviderIdentity("google", tokens, request),
    (error) => error instanceof AuthError && error.code === "provider_error",
  );
});

test("Discord identity resolution derives a displayable avatar URL", async () => {
  const request: typeof fetch = async () =>
    Response.json({
      id: "123",
      username: "demo-user",
      global_name: "Demo User",
      email: "demo@example.com",
      verified: true,
      avatar: "abc",
    });

  const identity = await resolveProviderIdentity("discord", tokens, request);
  assert.equal(identity.emailVerified, true);
  assert.equal(
    identity.claims.avatar_url,
    "https://cdn.discordapp.com/avatars/123/abc.png",
  );
});

test("provider profile responses are bounded", async () => {
  const request: typeof fetch = async () =>
    new Response("x".repeat(65 * 1_024), {
      headers: { "Content-Length": String(65 * 1_024) },
    });

  await assert.rejects(
    resolveProviderIdentity("google", tokens, request),
    (error) => error instanceof AuthError && error.code === "provider_error",
  );
});
