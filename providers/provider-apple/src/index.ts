import type { AuthPlugin, AuthUser } from "@ngriffin_uk/auth-core";
import {
  createOAuthProvider,
  defineOAuthProvider,
  type OAuthOperations,
  type OAuthProviderPluginOptions,
} from "@ngriffin_uk/auth-oauth2";
import { signJwt } from "@ngriffin_uk/auth-jwt";

export const appleDefinition = defineOAuthProvider({
  name: "apple",
  authorizationEndpoint: "https://appleid.apple.com/auth/authorize",
  tokenEndpoint: "https://appleid.apple.com/auth/token",
  pkce: false,
  clientAuthentication: "body",
});

export interface AppleOptions<User extends AuthUser>
  extends Omit<
    OAuthProviderPluginOptions<User>,
    "clientAuthentication" | "clientSecret"
  > {
  readonly teamId: string;
  readonly keyId: string;
  readonly privateKey: CryptoKey;
  readonly clock?: () => Date;
}

export function createAppleAuth<User extends AuthUser>(
  options: AppleOptions<User>
): AuthPlugin<"apple", OAuthOperations<User>, User> {
  const { teamId, keyId, privateKey, clock, ...oauthOptions } = options;
  return createOAuthProvider(appleDefinition, {
    ...oauthOptions,
    clientAuthentication: "body",
    clientSecret: async () => {
      const issuedAt = Math.floor((clock?.() ?? new Date()).getTime() / 1_000);
      return signJwt(
        {
          iss: teamId,
          sub: options.clientId,
          aud: "https://appleid.apple.com",
          iat: issuedAt,
          exp: issuedAt + 180 * 24 * 60 * 60,
        },
        {
          algorithm: "ES256",
          key: privateKey,
          header: { kid: keyId },
        }
      );
    },
  });
}

export function importApplePrivateKey(pkcs8: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    Uint8Array.from(pkcs8).buffer,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
}
