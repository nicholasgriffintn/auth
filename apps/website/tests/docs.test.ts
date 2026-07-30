import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { docs } from "../src/generated/docs.ts";

test("every package and provider README is represented exactly once", async () => {
  assert.equal(docs.length, 46);
  assert.equal(new Set(docs.map((entry) => entry.name)).size, docs.length);
  assert.equal(new Set(docs.map((entry) => entry.url)).size, docs.length);
  assert.equal(
    docs.filter((entry) => entry.kind === "package").length,
    13,
  );
  assert.equal(
    docs.filter((entry) => entry.kind === "provider").length,
    33,
  );

  for (const entry of docs) {
    const readme = await readFile(new URL(`../../../${entry.source}`, import.meta.url), "utf8");
    assert.equal(entry.markdown, readme, `${entry.name} is out of date`);
  }
});

test("the built site contains the security header rules and logo", async () => {
  const headers = await readFile(
    new URL("../dist/_headers", import.meta.url),
    "utf8",
  );
  const logo = await readFile(
    new URL("../dist/auth-logo.png", import.meta.url),
  );
  assert.match(headers, /Content-Security-Policy:/u);
  assert.match(headers, /X-Frame-Options: DENY/u);
  assert.ok(logo.byteLength > 100_000);
});
