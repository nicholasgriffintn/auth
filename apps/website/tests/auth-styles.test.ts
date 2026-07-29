import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const stylesheet = await readFile(
  new URL("../src/styles.css", import.meta.url),
  "utf8",
);

test("passkey challenge actions stack the primary and fallback controls", () => {
  assert.match(
    stylesheet,
    /\[data-auth-challenge="webauthn"\] \.auth-actions\s*\{[^}]*display:\s*grid;[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\);/su,
  );
  assert.match(
    stylesheet,
    /\[data-auth-challenge="webauthn"\] \.auth-link-button\s*\{[^}]*justify-self:\s*center;[^}]*line-height:\s*1\.4;[^}]*text-align:\s*center;/su,
  );
});
