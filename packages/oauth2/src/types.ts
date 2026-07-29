import type {
  AuthFlowResult,
  AuthUser,
  ExternalIdentity,
} from "@ngriffin_uk/auth-core";
import type {
  JwtAlgorithm,
  JwtClaims,
  JwtKeyResolver,
} from "@ngriffin_uk/auth-jwt";

export type ClientAuthentication = "basic" | "body" | "none";
export type ClientSecretProvider = () => string | Promise<string>;
export type OAuthTokenGrant =
  | "authorization_code"
  | "refresh_token"
  | "revoke";

export interface OAuthStateRecord {
  readonly stateHash: string;
  readonly provider: string;
  readonly codeVerifier?: string;
  readonly nonce?: string;
  readonly redirectUri?: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
}

export interface OAuthStateStore {
  create(state: OAuthStateRecord): Promise<void>;
  consumeByStateHash(stateHash: string): Promise<OAuthStateRecord | null>;
}

export interface OAuthTokenSet {
  readonly accessToken: string;
  readonly tokenType: string;
  readonly expiresAt?: Date;
  readonly refreshToken?: string;
  readonly idToken?: string;
  readonly scopes?: readonly string[];
  readonly values: Readonly<Record<string, unknown>>;
}

export interface OidcConfig {
  readonly issuer: string | readonly string[];
  readonly audience?: string | readonly string[];
  readonly algorithms: readonly JwtAlgorithm[];
  readonly key: CryptoKey | JwtKeyResolver;
}

export interface OAuthProviderConfig<
  Name extends string,
  User extends AuthUser,
> {
  readonly name: Name;
  readonly clientId: string;
  readonly clientSecret?: string | ClientSecretProvider;
  readonly redirectUri?: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly revocationEndpoint?: string;
  readonly scopes?: readonly string[];
  readonly clientAuthentication?: ClientAuthentication;
  readonly pkce?: boolean;
  readonly clientIdParameter?: string;
  readonly scopeSeparator?: " " | ",";
  readonly tokenParameters?: Partial<
    Readonly<Record<OAuthTokenGrant, Readonly<Record<string, string>>>>
  >;
  readonly tokenResponsePath?: readonly string[];
  readonly tokenHeaders?: Readonly<Record<string, string>>;
  readonly authorizationParameters?: Readonly<Record<string, string>>;
  readonly stateStore: OAuthStateStore;
  readonly stateTtlMs?: number;
  readonly fetch?: typeof globalThis.fetch;
  readonly oidc?: OidcConfig;
  readonly resolveIdentity: (
    tokens: OAuthTokenSet,
    idTokenClaims: JwtClaims | null
  ) => Promise<ExternalIdentity>;
}

export interface StartAuthorizationOptions {
  readonly scopes?: readonly string[];
  readonly authorizationParameters?: Readonly<Record<string, string>>;
}

export interface OAuthOperations<User extends AuthUser> {
  startAuthorization(options?: StartAuthorizationOptions): Promise<URL>;
  completeAuthorization(input: {
    readonly code: string;
    readonly state: string;
  }): Promise<AuthFlowResult<User>>;
  refresh(refreshToken: string, scopes?: readonly string[]): Promise<OAuthTokenSet>;
  revoke(token: string): Promise<void>;
}
