import {
  createAuth,
  type ChallengeStore,
  type IdentityStore,
  type SessionStore,
  type UserStore,
} from "@ngriffin_uk/auth-core";
import type { OAuthStateStore } from "@ngriffin_uk/auth-oauth2";
import type { OtpStore } from "@ngriffin_uk/auth-otp";
import type { PasswordStore } from "@ngriffin_uk/auth-password";
import type { WebAuthnStore } from "@ngriffin_uk/auth-webauthn";

import type { AuthStore } from "./auth-store";
import type { AuthEncryption } from "./encryption";
import type { DemoUser } from "./types";

type AuthStoreStub = DurableObjectStub<AuthStore>;

export function createBaseAuth(
  store: AuthStoreStub,
  challenges?: ChallengeStore,
) {
  const users: UserStore<DemoUser> = {
    findById: (userId) => store.findUser(userId),
  };
  const sessions: SessionStore = {
    create: (session) => store.createSession(session),
    findByTokenHash: (tokenHash) => store.findSession(tokenHash),
    deleteByTokenHash: (tokenHash) => store.deleteSession(tokenHash),
  };
  const identities: IdentityStore<DemoUser> = {
    findUser: (provider, providerSubject) =>
      store.findUserByIdentity(provider, providerSubject),
    resolve: (identity) => store.resolveIdentity(identity),
  };

  return createAuth({
    users,
    sessions,
    identities,
    ...(challenges ? { challenges } : {}),
  });
}

export function createOAuthStateStore(
  store: AuthStoreStub,
): OAuthStateStore {
  return {
    create: (state) => store.createOAuthState(state),
    consumeByStateHash: (stateHash) => store.consumeOAuthState(stateHash),
  };
}

export function createPasswordStore(
  store: AuthStoreStub,
): PasswordStore<DemoUser> {
  return {
    findByEmail: (email) => store.findPasswordAccountByEmail(email),
    findByUserId: (userId) => store.findPasswordAccountByUserId(userId),
    create: (input) => store.createPasswordAccount(input),
    updatePassword: (userId, passwordHash) =>
      store.updatePassword(userId, passwordHash),
    markEmailVerified: (userId) => store.markEmailVerified(userId),
  };
}

export function createChallengeStore(
  store: AuthStoreStub,
  encryption: AuthEncryption,
): ChallengeStore {
  return {
    async create(challenge) {
      await store.createChallenge({
        tokenHash: challenge.tokenHash,
        provider: challenge.provider,
        kind: challenge.kind,
        payload: await encryption.encryptJson(
          challenge.payload,
          challengeContext(
            challenge.tokenHash,
            challenge.provider,
            challenge.kind,
          ),
        ),
        createdAt: challenge.createdAt,
        expiresAt: challenge.expiresAt,
        attempts: challenge.attempts,
      });
    },
    async consumeByTokenHash(tokenHash) {
      const challenge = await store.consumeChallenge(tokenHash);
      if (!challenge) return null;
      return {
        tokenHash: challenge.tokenHash,
        provider: challenge.provider,
        kind: challenge.kind,
        payload: await encryption.decryptJson(
          challenge.payload,
          challengeContext(
            challenge.tokenHash,
            challenge.provider,
            challenge.kind,
          ),
        ),
        createdAt: challenge.createdAt,
        expiresAt: challenge.expiresAt,
        attempts: challenge.attempts,
      };
    },
  };
}

export function createOtpStore(
  store: AuthStoreStub,
  encryption: AuthEncryption,
): OtpStore {
  return {
    async saveCredential(input) {
      await store.saveOtpCredential({
        userId: input.userId,
        secret: await encryption.encryptBytes(
          input.secret,
          otpContext(input.userId),
        ),
        lastAcceptedStep: input.lastAcceptedStep.toString(),
        recoveryCodeHashes: input.recoveryCodeHashes,
      });
    },
    async findCredential(userId) {
      const credential = await store.findOtpCredential(userId);
      if (!credential) return null;
      return {
        secret: await encryption.decryptBytes(
          credential.secret,
          otpContext(userId),
        ),
        lastAcceptedStep: BigInt(credential.lastAcceptedStep),
      };
    },
    advanceStep: (userId, step) =>
      store.advanceOtpStep(userId, step.toString()),
    consumeRecoveryCode: (userId, codeHash) =>
      store.consumeRecoveryCode(userId, codeHash),
  };
}

export function createWebAuthnStore(store: AuthStoreStub): WebAuthnStore {
  return {
    saveCredential: (credential) =>
      store.saveWebAuthnCredential(credential),
    findCredential: (credentialId) =>
      store.findWebAuthnCredential(credentialId),
    listCredentials: (userId) =>
      store.listWebAuthnCredentials(userId),
    updateSignCount: (input) =>
      store.updateWebAuthnSignCount({
        ...input,
        updatedAt: new Date(),
      }),
  };
}

function challengeContext(
  tokenHash: string,
  provider: string,
  kind: string,
): string {
  return `challenge:${tokenHash}:${provider}:${kind}`;
}

function otpContext(userId: string): string {
  return `otp:${userId}`;
}
