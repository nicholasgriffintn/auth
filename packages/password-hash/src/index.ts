export interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(password: string, passwordHash: string): Promise<boolean>;
}

export interface PasswordHashVerification {
  readonly valid: boolean;
  readonly needsRehash: boolean;
}

export interface UpgradeablePasswordHasher extends PasswordHasher {
  verifyAndCheck(
    password: string,
    passwordHash: string
  ): Promise<PasswordHashVerification>;
}
