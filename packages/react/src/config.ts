import type {
  AuthCapabilities,
  AuthClassName,
  AuthCopy,
  AuthField,
  AuthProviderConfig,
  ResolvedAuthUiConfig,
} from "./types.js";

export const DEFAULT_COPY: AuthCopy = {
  signInTitle: "Sign in",
  signInSubmit: "Sign in",
  signUpTitle: "Create an account",
  signUpSubmit: "Create account",
  recoveryTitle: "Reset your password",
  recoverySubmit: "Send reset instructions",
  codeLabel: "Verification code",
  codeSubmit: "Verify",
  passwordLabel: "Password",
  newPasswordLabel: "New password",
  confirmPasswordLabel: "Confirm password",
  continueLabel: "Continue",
  passkeyLabel: "Continue with a passkey",
  securityTitle: "Sign-in security",
  totpTitle: "Authenticator app",
  totpDescription: "Use time-based verification codes from an authenticator app.",
  totpSetupLabel: "Set up authenticator",
  totpConfiguredLabel: "Configured",
  passkeyTitle: "Passkeys",
  passkeyDescription: "Use your device, fingerprint or security key.",
  passkeySetupLabel: "Add a passkey",
  passkeyChallengeTitle: "Verify with your passkey",
  totpOrRecoveryLabel: "Use an authenticator or recovery code",
  totpOrRecoveryCodeLabel: "Authenticator or recovery code",
  totpOrRecoveryDescription: "Enter the six-digit code or one of your saved recovery codes.",
  recoveryCodesLabel: "Save these recovery codes somewhere safe. Each code can be used once.",
  cancelLabel: "Cancel",
  resendLabel: "Resend code",
  genericError: "Authentication could not be completed.",
  unsupportedChallenge: "This authentication challenge is not supported.",
};

export const DEFAULT_CAPABILITIES: Required<AuthCapabilities> = {
  password: true,
  passkeys: false,
  signUp: true,
  recovery: true,
  signOut: true,
};

export const DEFAULT_SIGN_IN_FIELDS: readonly AuthField[] = [
  {
    name: "email",
    label: "Email",
    type: "email",
    autoComplete: "username",
    inputMode: "email",
    required: true,
  },
  {
    name: "password",
    label: "Password",
    type: "password",
    autoComplete: "current-password",
    required: true,
  },
];

export const DEFAULT_SIGN_UP_FIELDS: readonly AuthField[] = [
  {
    name: "email",
    label: "Email",
    type: "email",
    autoComplete: "email",
    inputMode: "email",
    required: true,
  },
  {
    name: "password",
    label: "Password",
    type: "password",
    autoComplete: "new-password",
    required: true,
    minLength: 8,
  },
  {
    name: "confirmPassword",
    label: "Confirm password",
    type: "password",
    autoComplete: "new-password",
    required: true,
    validate(value, values) {
      return value === values["password"] ? null : "Passwords do not match.";
    },
  },
];

export function resolveConfig<User>(config: AuthProviderConfig<User>) {
  return {
    ...config,
    capabilities: {
      ...DEFAULT_CAPABILITIES,
      ...config.capabilities,
    },
    copy: {
      ...DEFAULT_COPY,
      ...config.copy,
    },
    signInFields: config.signInFields ?? DEFAULT_SIGN_IN_FIELDS,
    signUpFields: config.signUpFields ?? DEFAULT_SIGN_UP_FIELDS,
    providers: config.providers ?? [],
  };
}

export function className(
  config: Pick<AuthProviderConfig, "classNames">,
  key: AuthClassName
): string {
  return config.classNames?.[key] ?? `auth-${toKebabCase(key)}`;
}

export function uiConfig<User>(
  config: ReturnType<typeof resolveConfig<User>>
): ResolvedAuthUiConfig {
  return {
    capabilities: config.capabilities,
    copy: config.copy,
    providers: config.providers,
    signInFields: config.signInFields,
    signUpFields: config.signUpFields,
    ...(config.classNames ? { classNames: config.classNames } : {}),
    ...(config.renderProviderIcon
      ? { renderProviderIcon: config.renderProviderIcon }
      : {}),
    ...(config.renderTotpQrCode
      ? { renderTotpQrCode: config.renderTotpQrCode }
      : {}),
    ...(config.renderUnsupportedChallenge
      ? { renderUnsupportedChallenge: config.renderUnsupportedChallenge }
      : {}),
    ...(config.resolveWebAuthn
      ? { resolveWebAuthn: config.resolveWebAuthn }
      : {}),
  };
}

function toKebabCase(value: string): string {
  return value.replace(/[A-Z]/gu, (match) => `-${match.toLowerCase()}`);
}
