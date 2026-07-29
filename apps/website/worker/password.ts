import { AuthError } from "@ngriffin_uk/auth-core";
import {
  passwordAuth,
  type PasswordInput,
  type PasswordOperations,
} from "@ngriffin_uk/auth-password";
import { createPbkdf2Hasher } from "@ngriffin_uk/auth-password-hash/pbkdf2";

import type { AuthStore } from "./auth-store";
import {
  createBaseAuth,
  createPasswordStore,
} from "./storage-adapters.ts";
import type { DemoUser } from "./types";

const hasher = createPbkdf2Hasher();

export function passwordOperations(
  store: DurableObjectStub<AuthStore>,
): PasswordOperations<DemoUser> {
  return createBaseAuth(store).use(
    passwordAuth({
      store: createPasswordStore(store),
      hasher,
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
