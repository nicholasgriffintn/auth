import assert from "node:assert/strict";
import { test } from "node:test";

import { resolveRoute } from "../src/lib/routes.ts";
import {
  canonicalOrigin,
  parseOAuthRoute,
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
  assert.deepEqual(parseOAuthRoute("/api/oauth/google/callback"), {
    provider: "google",
    action: "callback",
  });
  assert.equal(parseOAuthRoute("/api/oauth/reddit/start"), null);
  assert.equal(parseOAuthRoute("/api/oauth/github/delete"), null);
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
