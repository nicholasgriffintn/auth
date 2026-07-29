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

  const identity = await resolveProviderIdentity("github", tokens, { request });
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

test("Amazon Cognito identity resolution rejects a response without a subject", async () => {
  const request: typeof fetch = async (input) => {
    assert.equal(
      String(input),
      "https://example.auth.eu-west-2.amazoncognito.com/oauth2/userInfo",
    );
    return Response.json({ email: "person@example.com" });
  };

  await assert.rejects(
    resolveProviderIdentity("amazon-cognito", tokens, {
      request,
      cognitoUserInfoEndpoint:
        "https://example.auth.eu-west-2.amazoncognito.com/oauth2/userInfo",
    }),
    (error) => error instanceof AuthError && error.code === "provider_error",
  );
});

test("provider identifiers and persisted claim strings are bounded", async () => {
  const oversizedSubjectRequest: typeof fetch = async () =>
    Response.json({ sub: "x".repeat(257) });
  await assert.rejects(
    resolveProviderIdentity("amazon-cognito", tokens, {
      request: oversizedSubjectRequest,
      cognitoUserInfoEndpoint:
        "https://example.auth.eu-west-2.amazoncognito.com/oauth2/userInfo",
    }),
    (error) => error instanceof AuthError && error.code === "provider_error",
  );

  const boundedClaimsRequest: typeof fetch = async () =>
    Response.json({
      sub: "subject-1",
      name: "x".repeat(2_049),
      picture: "https://example.com/avatar.png",
    });
  const identity = await resolveProviderIdentity(
    "amazon-cognito",
    tokens,
    {
      request: boundedClaimsRequest,
      cognitoUserInfoEndpoint:
        "https://example.auth.eu-west-2.amazoncognito.com/oauth2/userInfo",
    },
  );
  assert.deepEqual(identity.claims, {
    sub: "subject-1",
    picture: "https://example.com/avatar.png",
  });
});

test("Amazon Cognito identity resolution maps verified profile claims", async () => {
  const request: typeof fetch = async () =>
    Response.json({
      sub: "123",
      username: "demo-user",
      name: "Demo User",
      email: "demo@example.com",
      email_verified: true,
      picture: "https://example.com/avatar.png",
    });

  const identity = await resolveProviderIdentity("amazon-cognito", tokens, {
    request,
    cognitoUserInfoEndpoint:
      "https://example.auth.eu-west-2.amazoncognito.com/oauth2/userInfo",
  });
  assert.equal(identity.emailVerified, true);
  assert.equal(identity.provider, "amazon-cognito");
  assert.equal(identity.claims.picture, "https://example.com/avatar.png");
});

test("provider profile responses are bounded", async () => {
  const request: typeof fetch = async () =>
    new Response("x".repeat(65 * 1_024), {
      headers: { "Content-Length": String(65 * 1_024) },
    });

  await assert.rejects(
    resolveProviderIdentity("amazon-cognito", tokens, {
      request,
      cognitoUserInfoEndpoint:
        "https://example.auth.eu-west-2.amazoncognito.com/oauth2/userInfo",
    }),
    (error) => error instanceof AuthError && error.code === "provider_error",
  );
});
