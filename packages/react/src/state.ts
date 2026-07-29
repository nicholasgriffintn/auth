import type {
  AuthClientChallenge,
  AuthClientResult,
  AuthView,
} from "./types.js";

export interface AuthState {
  readonly view: AuthView;
  readonly challenge?: AuthClientChallenge;
  readonly submitting: boolean;
  readonly error?: string;
  readonly status?: string;
}

export type AuthStateAction =
  | { readonly type: "navigate"; readonly view: Exclude<AuthView, "challenge"> }
  | { readonly type: "submit" }
  | { readonly type: "error"; readonly message: string }
  | { readonly type: "result"; readonly result: AuthClientResult }
  | { readonly type: "status"; readonly message: string };

export const INITIAL_AUTH_STATE: AuthState = {
  view: "sign_in",
  submitting: false,
};

export function authStateReducer(
  state: AuthState,
  action: AuthStateAction
): AuthState {
  switch (action.type) {
    case "navigate":
      return {
        view: action.view,
        submitting: false,
      };
    case "submit":
      {
        const {
          error: _error,
          status: _status,
          ...current
        } = state;
        return {
          ...current,
          submitting: true,
        };
      }
    case "error":
      {
        const { status: _status, ...current } = state;
        return {
          ...current,
          submitting: false,
          error: action.message,
        };
      }
    case "status":
      {
        const { error: _error, ...current } = state;
        return {
          ...current,
          submitting: false,
          status: action.message,
        };
      }
    case "result":
      return stateFromResult(state, action.result);
  }
}

function stateFromResult(
  state: AuthState,
  result: AuthClientResult
): AuthState {
  if ("challenge" in result) {
    return {
      view: "challenge",
      challenge: result.challenge,
      submitting: false,
    };
  }
  if (result.status === "completed") {
    return {
      view: result.next ?? "sign_in",
      submitting: false,
      status: "Authentication step completed.",
    };
  }
  const { error: _error, ...current } = state;
  return {
    ...current,
    submitting: false,
  };
}
