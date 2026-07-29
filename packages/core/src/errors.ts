export type AuthErrorCode =
  | "challenge_expired"
  | "challenge_mismatch"
  | "duplicate_plugin"
  | "email_in_use"
  | "identity_conflict"
  | "insecure_runtime"
  | "invalid_callback"
  | "invalid_credentials"
  | "invalid_input"
  | "oauth_exchange_failed"
  | "provider_error"
  | "provider_not_found"
  | "rate_limited"
  | "session_expired"
  | "storage_error"
  | "unsupported_operation";

const DEFAULT_MESSAGES: Record<AuthErrorCode, string> = {
  challenge_expired: "The authentication challenge is invalid or expired.",
  challenge_mismatch: "The authentication challenge does not match this flow.",
  duplicate_plugin: "Authentication provider is already registered.",
  email_in_use: "An account already exists for this email address.",
  identity_conflict: "This identity is already linked to another account.",
  insecure_runtime: "Secure cryptography is unavailable.",
  invalid_callback: "The authentication callback is invalid or expired.",
  invalid_credentials: "The email address or password is incorrect.",
  invalid_input: "The authentication request is invalid.",
  oauth_exchange_failed: "The authentication provider rejected the request.",
  provider_error: "The authentication provider is unavailable.",
  provider_not_found: "The authentication provider is not configured.",
  rate_limited: "Too many authentication attempts. Try again later.",
  session_expired: "The session is invalid or expired.",
  storage_error: "Authentication storage is unavailable.",
  unsupported_operation: "This authentication operation is not supported.",
};

export interface AuthErrorOptions {
  readonly cause?: unknown;
  readonly retryable?: boolean;
}

export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly retryable: boolean;

  constructor(
    code: AuthErrorCode,
    message = DEFAULT_MESSAGES[code],
    options: AuthErrorOptions = {}
  ) {
    super(message, { cause: options.cause });
    this.name = "AuthError";
    this.code = code;
    this.retryable = options.retryable ?? false;
  }
}

export function toStorageError(cause: unknown): AuthError {
  if (cause instanceof AuthError) {
    return cause;
  }
  return new AuthError("storage_error", undefined, {
    cause,
    retryable: true,
  });
}
