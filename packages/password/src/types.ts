import type {
  AuthFlowResult,
  AuthUser,
} from "@ngriffin_uk/auth-core";
import type { PasswordHasher } from "@ngriffin_uk/auth-password-hash";

export type { PasswordHasher } from "@ngriffin_uk/auth-password-hash";

export interface PasswordAccount<User extends AuthUser> {
  readonly user: User;
  readonly passwordHash: string;
  readonly emailVerified: boolean;
}

export interface CreatePasswordAccountInput {
  readonly email: string;
  readonly passwordHash: string;
  readonly emailVerified: boolean;
}

export interface PasswordStore<User extends AuthUser> {
  findByEmail(email: string): Promise<PasswordAccount<User> | null>;
  findByUserId(userId: string): Promise<PasswordAccount<User> | null>;
  create(input: CreatePasswordAccountInput): Promise<User>;
  updatePassword(userId: string, passwordHash: string): Promise<void>;
  markEmailVerified(userId: string): Promise<void>;
}

export interface PasswordPolicy {
  validate(password: string): string | null;
}

export interface PasswordPluginConfig<User extends AuthUser> {
  readonly store: PasswordStore<User>;
  readonly hasher: PasswordHasher;
  readonly policy?: PasswordPolicy;
  readonly normaliseEmail?: (email: string) => string;
  readonly emailVerification?: {
    readonly send: (input: PasswordDelivery<User>) => Promise<void>;
  };
  readonly passwordReset?: {
    readonly send: (input: PasswordDelivery<User>) => Promise<void>;
  };
  readonly onPasswordChanged?: (user: User) => void | Promise<void>;
}

export interface PasswordDelivery<User extends AuthUser> {
  readonly user: User;
  readonly token: string;
  readonly expiresAt: Date;
}

export interface PasswordInput {
  readonly email: string;
  readonly password: string;
}

export interface PasswordOperations<User extends AuthUser> {
  verifyCredentials(input: PasswordInput): Promise<User>;
  signUp(input: PasswordInput): Promise<AuthFlowResult<User>>;
  signIn(input: PasswordInput): Promise<AuthFlowResult<User>>;
  verifyEmail(input: {
    readonly token: string;
  }): Promise<AuthFlowResult<User>>;
  resendVerification(email: string): Promise<void>;
  requestPasswordReset(email: string): Promise<void>;
  resetPassword(input: {
    readonly token: string;
    readonly newPassword: string;
  }): Promise<void>;
  changePassword(input: {
    readonly userId: string;
    readonly currentPassword: string;
    readonly newPassword: string;
  }): Promise<void>;
}
