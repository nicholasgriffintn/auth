import {
  normaliseEmail as defaultNormaliseEmail,
  type AuthPlugin,
  type AuthUser,
} from "@ngriffin_uk/auth-core";

import {
  changePassword,
  requestPasswordReset,
  resendVerification,
  resetPassword,
  signIn,
  signUp,
  verifyCredentials,
  verifyEmail,
  type PasswordRuntime,
} from "./flows.js";
import type {
  PasswordOperations,
  PasswordPluginConfig,
} from "./types.js";
import { defaultPasswordPolicy } from "./validation.js";

export function passwordAuth<User extends AuthUser>(
  config: PasswordPluginConfig<User>
): AuthPlugin<"password", PasswordOperations<User>, User> {
  return {
    name: "password",
    install(context) {
      const runtime: PasswordRuntime<User> = {
        context,
        config,
        normaliseEmail: config.normaliseEmail ?? defaultNormaliseEmail,
        policy: config.policy ?? defaultPasswordPolicy,
      };
      return {
        verifyCredentials: (input) => verifyCredentials(runtime, input),
        signUp: (input) => signUp(runtime, input),
        signIn: (input) => signIn(runtime, input),
        verifyEmail: (input) => verifyEmail(runtime, input.token),
        resendVerification: (email) => resendVerification(runtime, email),
        requestPasswordReset: (email) =>
          requestPasswordReset(runtime, email),
        resetPassword: (input) => resetPassword(runtime, input),
        changePassword: (input) => changePassword(runtime, input),
      };
    },
  };
}
