import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { AuthError } from "@ngriffin_uk/auth-core";

import {
  createDiscoveredOidcProvider,
  defineOAuthProvider,
  discoverOpenIdConfiguration,
} from "./index.js";

describe("OIDC discovery and provider definitions", () => {
  it("validates the issuer and secure metadata endpoints", async () => {
    const configuration = await discoverOpenIdConfiguration(
      "https://issuer.example",
      {
        fetch: async () =>
          new Response(
            JSON.stringify({
              issuer: "https://issuer.example",
              authorization_endpoint: "https://issuer.example/authorize",
              token_endpoint: "https://issuer.example/token",
              jwks_uri: "https://issuer.example/jwks",
              code_challenge_methods_supported: ["S256"],
              id_token_signing_alg_values_supported: ["RS256"],
            })
          ),
      }
    );

    assert.equal(
      configuration.authorizationEndpoint,
      "https://issuer.example/authorize"
    );
    assert.deepEqual(configuration.codeChallengeMethodsSupported, ["S256"]);
  });

  it("rejects issuer substitution and unsafe provider definitions", async () => {
    await assert.rejects(
      discoverOpenIdConfiguration("https://issuer.example", {
        fetch: async () =>
          new Response(
            JSON.stringify({
              issuer: "https://attacker.example",
              authorization_endpoint: "https://issuer.example/authorize",
              token_endpoint: "https://issuer.example/token",
              jwks_uri: "https://issuer.example/jwks",
            })
          ),
      }),
      (error) => error instanceof AuthError && error.code === "provider_error"
    );
    assert.throws(() =>
      defineOAuthProvider({
        name: "unsafe",
        authorizationEndpoint: "http://provider.example/authorize",
        tokenEndpoint: "https://provider.example/token",
        pkce: true,
      })
    );
  });

  it("composes discovery and a pinned remote-key OIDC provider", async () => {
    const plugin = await createDiscoveredOidcProvider(
      "enterprise",
      "https://issuer.example",
      {
        clientId: "client-id",
        redirectUri: "https://app.example/callback",
        algorithms: ["RS256"],
        stateStore: {
          async create() {},
          async consumeByStateHash() {
            return null;
          },
        },
        fetch: async () =>
          new Response(
            JSON.stringify({
              issuer: "https://issuer.example",
              authorization_endpoint: "https://issuer.example/authorize",
              token_endpoint: "https://issuer.example/token",
              jwks_uri: "https://issuer.example/jwks",
              code_challenge_methods_supported: ["S256"],
              id_token_signing_alg_values_supported: ["RS256"],
            })
          ),
        async resolveIdentity() {
          return {
            provider: "enterprise",
            providerSubject: "subject",
            claims: {},
          };
        },
      }
    );

    assert.equal(plugin.name, "enterprise");
  });
});
