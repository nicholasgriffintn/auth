import assert from "node:assert/strict";
import { test } from "node:test";

import { resolveRoute } from "../src/lib/routes.ts";
import {
  canonicalOrigin,
  parseMfaRoute,
  parseOAuthRoute,
  parsePasswordRoute,
  parseSecurityRoute,
  readJsonObject,
  sessionCookie,
} from "../worker/http.ts";

test("site routes resolve nested docs and normalise trailing slashes", () => {
  assert.deepEqual(resolveRoute("/"), { name: "home" });
  assert.deepEqual(resolveRoute("/docs/"), { name: "docs" });
  assert.deepEqual(resolveRoute("/docs/providers/github/"), {
    name: "doc",
    url: "/docs/providers/github",
  });
  assert.deepEqual(resolveRoute("/missing"), { name: "not-found" });
});

test("OAuth routes accept only implemented providers and actions", () => {
  assert.deepEqual(parseOAuthRoute("/api/oauth/github/start"), {
    provider: "github",
    action: "start",
  });
  assert.deepEqual(parseOAuthRoute("/api/oauth/amazon-cognito/callback"), {
    provider: "amazon-cognito",
    action: "callback",
  });
  assert.equal(parseOAuthRoute("/api/oauth/google/callback"), null);
  assert.equal(parseOAuthRoute("/api/oauth/reddit/start"), null);
  assert.equal(parseOAuthRoute("/api/oauth/github/delete"), null);
});

test("password routes accept only sign-in and sign-up actions", () => {
  assert.equal(parsePasswordRoute("/api/password/sign-in"), "sign-in");
  assert.equal(parsePasswordRoute("/api/password/sign-up"), "sign-up");
  assert.equal(parsePasswordRoute("/api/password/reset"), null);
  assert.equal(parsePasswordRoute("/api/oauth/password/start"), null);
});

test("security routes accept only implemented enrolment operations", () => {
  assert.equal(parseSecurityRoute("/api/security/status"), "status");
  assert.equal(parseSecurityRoute("/api/security/totp/start"), "totp-start");
  assert.equal(
    parseSecurityRoute("/api/security/webauthn/verify"),
    "webauthn-verify",
  );
  assert.equal(parseSecurityRoute("/api/security/totp/remove"), null);
  assert.equal(parseSecurityRoute("/api/security/google/start"), null);
});

test("MFA routes accept only implemented sign-in verification operations", () => {
  assert.equal(parseMfaRoute("/api/mfa/pending"), "pending");
  assert.equal(parseMfaRoute("/api/mfa/totp/verify"), "totp-verify");
  assert.equal(
    parseMfaRoute("/api/mfa/webauthn/verify"),
    "webauthn-verify",
  );
  assert.equal(parseMfaRoute("/api/mfa/totp/start"), null);
  assert.equal(parseMfaRoute("/api/mfa/recovery/verify"), null);
});

test("JSON request parsing rejects unbounded or malformed bodies", async () => {
  const valid = await readJsonObject(
    new Request("https://example.com/api/password/sign-in", {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({ email: "demo@example.com", password: "secret" }),
    }),
  );
  assert.equal(valid.email, "demo@example.com");

  await assert.rejects(
    readJsonObject(
      new Request("https://example.com/api/password/sign-in", {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: "{}",
      }),
    ),
  );
  await assert.rejects(
    readJsonObject(
      new Request("https://example.com/api/password/sign-in", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ value: "x".repeat(100) }),
      }),
      32,
    ),
  );
});

test("canonical origins reject paths, credentials and insecure hosts", () => {
  const request = new Request("https://auth.nicholasgriffin.dev/api/session");
  assert.equal(
    canonicalOrigin(request, {
      SITE_ORIGIN: "https://auth.nicholasgriffin.dev",
    }),
    "https://auth.nicholasgriffin.dev",
  );
  assert.throws(() =>
    canonicalOrigin(request, {
      SITE_ORIGIN: "https://example.com/path",
    }),
  );
  assert.throws(() =>
    canonicalOrigin(request, {
      SITE_ORIGIN: "http://example.com",
    }),
  );
});

test("session cookies use host-only secure authentication defaults", () => {
  const cookie = sessionCookie(
    "opaque value",
    new Date(Date.now() + 60_000),
  );
  assert.match(cookie, /^__Host-auth_session=/u);
  assert.match(cookie, /HttpOnly/u);
  assert.match(cookie, /SameSite=Lax/u);
  assert.match(cookie, /Secure/u);
  assert.match(cookie, /Path=\//u);
  assert.doesNotMatch(cookie, /Domain=/u);
});
