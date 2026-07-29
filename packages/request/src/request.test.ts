import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  readResponseText,
  requestWithTimeout,
  verifyRequestCsrf,
  verifyRequestOrigin,
} from "./index.js";

describe("request validation", () => {
  it("requires an exact scheme, host, and port match", () => {
    const allowed = ["https://example.com", "http://localhost:3000"];
    assert.equal(verifyRequestOrigin("https://example.com", allowed), true);
    assert.equal(verifyRequestOrigin("http://example.com", allowed), false);
    assert.equal(verifyRequestOrigin("https://example.com.evil.test", allowed), false);
    assert.equal(verifyRequestOrigin("http://localhost:3000", allowed), true);
    assert.equal(verifyRequestOrigin("http://localhost:3001", allowed), false);
  });

  it("allows safe methods without Origin and validates unsafe methods", () => {
    assert.equal(
      verifyRequestCsrf(
        { method: "GET", headers: new Headers() },
        ["https://example.com"]
      ),
      true
    );
    assert.equal(
      verifyRequestCsrf(
        {
          method: "POST",
          headers: new Headers({ Origin: "https://example.com" }),
        },
        ["https://example.com"]
      ),
      true
    );
    assert.equal(
      verifyRequestCsrf(
        {
          method: "POST",
          headers: new Headers({
            Origin: "https://example.com",
            "Sec-Fetch-Site": "cross-site",
          }),
        },
        ["https://example.com"]
      ),
      false
    );
  });
});

describe("outbound response limits", () => {
  it("reads responses within the configured limit", async () => {
    assert.equal(
      await readResponseText(new Response("response"), 8),
      "response"
    );
  });

  it("rejects oversized streamed responses", async () => {
    await assert.rejects(
      readResponseText(new Response("too large"), 4),
      /size limit/u
    );
  });

  it("aborts requests after the configured timeout", async () => {
    const request: typeof fetch = async (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("Aborted", "AbortError"))
        );
      });

    await assert.rejects(
      requestWithTimeout(request, "https://example.com", {}, 1),
      (error) => error instanceof DOMException && error.name === "AbortError"
    );
  });

  it("preserves caller cancellation while applying a timeout", async () => {
    const controller = new AbortController();
    const request: typeof fetch = async (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("Aborted", "AbortError"))
        );
        controller.abort();
      });

    await assert.rejects(
      requestWithTimeout(
        request,
        "https://example.com",
        { signal: controller.signal },
        10_000
      ),
      (error) => error instanceof DOMException && error.name === "AbortError"
    );
  });
});
