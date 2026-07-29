import { AuthError } from "@ngriffin_uk/auth-core";
import {
  passwordAuth,
  type PasswordInput,
  type PasswordOperations,
} from "@ngriffin_uk/auth-password";
import { createScryptHasher } from "@ngriffin_uk/auth-password-hash/node";

import type { AuthStore } from "./auth-store";
import {
  createBaseAuth,
  createPasswordStore,
} from "./storage-adapters.ts";
import type { DemoUser } from "./types";

export const demoPasswordHasher = createScryptHasher({
  cost: 2 ** 15,
  blockSize: 8,
  parallelism: 3,
  maxMemoryBytes: 64 * 1_024 * 1_024,
});

export function passwordOperations(
  store: DurableObjectStub<AuthStore>,
): PasswordOperations<DemoUser> {
  return createBaseAuth(store).use(
    passwordAuth({
      store: createPasswordStore(store),
      hasher: demoPasswordHasher,
    }),
  ).providers.password;
}

export function parsePasswordInput(
  value: Readonly<Record<string, unknown>>,
): PasswordInput {
  if (
    typeof value.email !== "string" ||
    typeof value.password !== "string"
  ) {
    throw new AuthError("invalid_input");
  }
  return { email: value.email, password: value.password };
}
