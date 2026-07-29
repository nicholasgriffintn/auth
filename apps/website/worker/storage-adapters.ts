import {
  createAuth,
  type IdentityStore,
  type SessionStore,
  type UserStore,
} from "@ngriffin_uk/auth-core";
import type { OAuthStateStore } from "@ngriffin_uk/auth-oauth2";

import type { AuthStore } from "./auth-store";
import type { DemoUser } from "./types";

type AuthStoreStub = DurableObjectStub<AuthStore>;

export function createBaseAuth(store: AuthStoreStub) {
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

  return createAuth({ users, sessions, identities });
}

export function createOAuthStateStore(
  store: AuthStoreStub,
): OAuthStateStore {
  return {
    create: (state) => store.createOAuthState(state),
    consumeByStateHash: (stateHash) => store.consumeOAuthState(stateHash),
  };
}
