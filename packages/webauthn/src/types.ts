import type { AuthFlowResult, AuthUser } from "@ngriffin_uk/auth-core";

export type WebAuthnAlgorithm = "ES256" | "RS256";

export interface WebAuthnCredential {
  readonly id: string;
  readonly userId: string;
  readonly publicKeyJwk: JsonWebKey;
  readonly algorithm: WebAuthnAlgorithm;
  readonly signCount: number;
  readonly transports?: readonly AuthenticatorTransport[];
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface WebAuthnStore {
  saveCredential(credential: WebAuthnCredential): Promise<void>;
  findCredential(credentialId: string): Promise<WebAuthnCredential | null>;
  listCredentials(userId: string): Promise<readonly WebAuthnCredential[]>;
  updateSignCount(input: {
    readonly credentialId: string;
    readonly previousSignCount: number;
    readonly signCount: number;
    readonly backedUp: boolean;
  }): Promise<boolean>;
}

export interface WebAuthnPluginConfig {
  readonly rpId: string;
  readonly rpName: string;
  readonly origins: readonly string[];
  readonly store: WebAuthnStore;
  readonly requireUserVerification?: boolean;
  readonly attestation?: "none" | "direct";
  readonly timeoutMs?: number;
}

export interface WebAuthnRegistrationResponse {
  readonly credentialId: string;
  readonly clientDataJSON: string;
  readonly attestationObject: string;
  readonly transports?: readonly AuthenticatorTransport[];
}

export interface WebAuthnAuthenticationResponse {
  readonly credentialId: string;
  readonly clientDataJSON: string;
  readonly authenticatorData: string;
  readonly signature: string;
  readonly userHandle?: string;
}

export interface WebAuthnOperations<User extends AuthUser> {
  startRegistration(input: {
    readonly userId: string;
    readonly userName: string;
    readonly displayName: string;
  }): Promise<AuthFlowResult<User>>;
  finishRegistration(input: {
    readonly token: string;
    readonly response: WebAuthnRegistrationResponse;
  }): Promise<AuthFlowResult<User>>;
  startAuthentication(userId?: string): Promise<AuthFlowResult<User>>;
  finishAuthentication(input: {
    readonly token: string;
    readonly response: WebAuthnAuthenticationResponse;
  }): Promise<AuthFlowResult<User>>;
}

export interface ParsedAuthenticatorData {
  readonly bytes: Uint8Array;
  readonly flags: number;
  readonly signCount: number;
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
  readonly credentialId?: Uint8Array;
  readonly credentialPublicKey?: JsonWebKey;
  readonly algorithm?: WebAuthnAlgorithm;
}
