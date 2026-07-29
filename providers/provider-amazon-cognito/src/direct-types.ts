import type {
  AuthFlowResult,
  AuthUser,
  ExternalIdentity,
} from "@ngriffin_uk/auth-core";

export type CognitoChoice =
  | "EMAIL_OTP"
  | "PASSWORD"
  | "SMS_OTP"
  | "WEB_AUTHN";

export interface CognitoTokenSet {
  readonly accessToken: string;
  readonly idToken?: string;
  readonly refreshToken?: string;
  readonly expiresAt: Date;
  readonly tokenType: string;
}

export interface CognitoSignUpEvent {
  readonly providerSubject: string;
  readonly username: string;
  readonly confirmed: boolean;
}

export interface AmazonCognitoDirectOptions<User extends AuthUser> {
  readonly region: string;
  readonly userPoolId: string;
  readonly clientId: string;
  readonly clientSecret?: string;
  readonly fetch?: typeof globalThis.fetch;
  readonly endpoint?: string;
  readonly maxResponseBytes?: number;
  readonly requestTimeoutMs?: number;
  readonly clientMetadata?: Readonly<Record<string, string>>;
  readonly onSignUp?: (event: CognitoSignUpEvent) => void | Promise<void>;
  readonly onTokens?: (input: {
    readonly user: User;
    readonly tokens: CognitoTokenSet;
    readonly identity: ExternalIdentity;
  }) => void | Promise<void>;
}

export interface CognitoSignUpInput {
  readonly username: string;
  readonly password: string;
  readonly attributes?: Readonly<Record<string, string>>;
  readonly clientMetadata?: Readonly<Record<string, string>>;
}

export interface CognitoDirectOperations<User extends AuthUser> {
  signUp(input: CognitoSignUpInput): Promise<AuthFlowResult<User>>;
  confirmSignUp(input: {
    readonly token: string;
    readonly code: string;
  }): Promise<void>;
  resendConfirmationCode(username: string): Promise<void>;
  signInPassword(input: {
    readonly username: string;
    readonly password: string;
  }): Promise<AuthFlowResult<User>>;
  startSignIn(input: {
    readonly username: string;
    readonly preferredChallenge?: CognitoChoice;
  }): Promise<AuthFlowResult<User>>;
  respondToCode(input: {
    readonly token: string;
    readonly code: string;
  }): Promise<AuthFlowResult<User>>;
  respondToPassword(input: {
    readonly token: string;
    readonly password: string;
  }): Promise<AuthFlowResult<User>>;
  respondToNewPassword(input: {
    readonly token: string;
    readonly newPassword: string;
    readonly attributes?: Readonly<Record<string, string>>;
  }): Promise<AuthFlowResult<User>>;
  selectChallenge(input: {
    readonly token: string;
    readonly challenge: CognitoChoice | "SOFTWARE_TOKEN_MFA";
  }): Promise<AuthFlowResult<User>>;
  respondToCustomChallenge(input: {
    readonly token: string;
    readonly answer: string;
  }): Promise<AuthFlowResult<User>>;
  respondToWebAuthn(input: {
    readonly token: string;
    readonly credential: string;
  }): Promise<AuthFlowResult<User>>;
  startMfaSetup(input: {
    readonly token: string;
    readonly accountName: string;
    readonly issuer: string;
  }): Promise<AuthFlowResult<User>>;
  verifyMfaSetup(input: {
    readonly token: string;
    readonly code: string;
  }): Promise<AuthFlowResult<User>>;
  forgotPassword(username: string): Promise<AuthFlowResult<User>>;
  confirmForgotPassword(input: {
    readonly token: string;
    readonly code: string;
    readonly newPassword: string;
  }): Promise<void>;
  changePassword(input: {
    readonly accessToken: string;
    readonly currentPassword: string;
    readonly newPassword: string;
  }): Promise<void>;
  refresh(input: {
    readonly username: string;
    readonly refreshToken: string;
  }): Promise<AuthFlowResult<User>>;
  revokeRefreshToken(refreshToken: string): Promise<void>;
  signOut(accessToken: string): Promise<void>;
}

export interface CognitoAuthenticationResult {
  readonly AccessToken?: string;
  readonly ExpiresIn?: number;
  readonly IdToken?: string;
  readonly RefreshToken?: string;
  readonly TokenType?: string;
}

export interface CognitoAuthResponse {
  readonly AvailableChallenges?: readonly string[];
  readonly ChallengeName?: string;
  readonly ChallengeParameters?: Readonly<Record<string, string>>;
  readonly Session?: string;
  readonly AuthenticationResult?: CognitoAuthenticationResult;
}
