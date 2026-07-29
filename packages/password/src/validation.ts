import { AuthError } from "@ngriffin_uk/auth-core";

import type { PasswordInput, PasswordPolicy } from "./types.js";

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;

export const defaultPasswordPolicy: PasswordPolicy = {
  validate(password) {
    if (password.length < 8) {
      return "Password must contain at least 8 characters.";
    }
    if (password.length > 1_024) {
      return "Password must contain no more than 1024 characters.";
    }
    return null;
  },
};

export function validatePasswordInput(
  input: PasswordInput,
  policy: PasswordPolicy
): void {
  if (!EMAIL_PATTERN.test(input.email) || input.email.length > 320) {
    throw new AuthError("invalid_input", "Enter a valid email address.");
  }
  const passwordError = policy.validate(input.password);
  if (passwordError) {
    throw new AuthError("invalid_input", passwordError);
  }
}
