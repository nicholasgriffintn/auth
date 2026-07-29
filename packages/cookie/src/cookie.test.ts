import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  parseCookies,
  serializeCookie,
  serializeExpiredCookie,
  serializeSessionCookie,
} from "./index.js";

describe("cookie primitives", () => {
  it("serialises secure session cookies", () => {
    assert.equal(
      serializeSessionCookie("__Host-session", "secret value", {
        maxAge: 60,
      }),
      "__Host-session=secret%20value; HttpOnly; Max-Age=60; Path=/; SameSite=Lax; Secure"
    );
  });

  it("parses values containing equals signs and ignores malformed pairs", () => {
    assert.deepEqual(
      [...parseCookies("first=a%3Db; malformed; second=value").entries()],
      [
        ["first", "a=b"],
        ["second", "value"],
      ]
    );
    assert.equal(
      parseCookies("session=host-value; session=domain-value").get("session"),
      "host-value"
    );
  });

  it("creates an immediately expired cookie", () => {
    assert.match(serializeExpiredCookie("session"), /Max-Age=0/u);
  });

  it("rejects insecure or injectable attributes", () => {
    assert.throws(() =>
      serializeCookie("session", "value", { sameSite: "none" })
    );
    assert.throws(() =>
      serializeCookie("session", "value", { path: "/; HttpOnly" })
    );
    assert.throws(() =>
      serializeCookie("__Host-session", "value", {
        path: "/",
        secure: true,
        domain: "example.com",
      })
    );
    assert.throws(() =>
      serializeCookie("__Secure-session", "value")
    );
    assert.throws(() =>
      serializeCookie("session", "value", {
        expires: new Date(Number.NaN),
      })
    );
  });
});
