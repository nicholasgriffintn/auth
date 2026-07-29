import assert from "node:assert/strict";
import { test } from "node:test";

import { providerSummaries } from "../worker/providers.ts";

test("the demo exposes password auth without credentials and gates OAuth providers", () => {
  assert.deepEqual(providerSummaries({}), [
    { id: "github", label: "GitHub", configured: false },
    { id: "password", label: "Self-rolled auth", configured: true },
    {
      id: "amazon-cognito",
      label: "Amazon Cognito",
      configured: false,
    },
  ]);

  const configured = providerSummaries({
    GITHUB_CLIENT_ID: "github-id",
    GITHUB_CLIENT_SECRET: "github-secret",
    COGNITO_DOMAIN: "demo.auth.eu-west-2.amazoncognito.com",
    COGNITO_CLIENT_ID: "cognito-id",
    COGNITO_CLIENT_SECRET: "cognito-secret",
  });
  assert.equal(configured[0]?.configured, true);
  assert.equal(configured[2]?.configured, true);
});
