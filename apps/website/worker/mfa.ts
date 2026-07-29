import { otpAuth } from "@ngriffin_uk/auth-otp";
import { webAuthn } from "@ngriffin_uk/auth-webauthn";

import type { AuthStore } from "./auth-store";
import { createAuthEncryption } from "./encryption.ts";
import {
  createBaseAuth,
  createChallengeStore,
  createOtpStore,
  createWebAuthnStore,
} from "./storage-adapters.ts";
import type { DemoUser, Env } from "./types";

export async function createDemoMfaAuth(
  store: DurableObjectStub<AuthStore>,
  env: Pick<Env, "AUTH_ENCRYPTION_KEY">,
  origin: string,
) {
  const encryption = await createAuthEncryption(env.AUTH_ENCRYPTION_KEY);
  return createBaseAuth(
    store,
    createChallengeStore(store, encryption),
  )
    .use(
      otpAuth<DemoUser>({
        issuer: "Auth package demo",
        store: createOtpStore(store, encryption),
      }),
    )
    .use(
      webAuthn<DemoUser>({
        rpId: new URL(origin).hostname,
        rpName: "Auth package demo",
        origins: [origin],
        store: createWebAuthnStore(store),
        requireUserVerification: true,
      }),
    );
}
