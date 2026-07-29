import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useReducer,
  type ReactNode,
} from "react";

import {
  resolveConfig,
  uiConfig,
} from "./config.js";
import { alternativeAuthChallenge } from "./challenge.js";
import {
  authStateReducer,
  INITIAL_AUTH_STATE,
  type AuthState,
} from "./state.js";
import type {
  AuthClientChallenge,
  AuthAnalyticsEvent,
  AuthProviderConfig,
  AuthRequest,
  ResolvedAuthUiConfig,
  AuthView,
} from "./types.js";

export interface AuthContextValue {
  readonly config: ResolvedAuthUiConfig;
  readonly state: AuthState;
  readonly navigate: (view: Exclude<AuthView, "challenge">) => void;
  readonly submit: (request: AuthRequest) => Promise<void>;
  readonly continueChallenge: (
    values: Readonly<Record<string, string>>
  ) => Promise<void>;
  readonly resendVerification: () => Promise<void>;
  readonly usePasskey: () => Promise<void>;
  readonly useAlternativeChallenge: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider<User>({
  children,
  config: rawConfig,
}: {
  readonly children: ReactNode;
  readonly config: AuthProviderConfig<User>;
}) {
  const resolvedConfig = useMemo(() => resolveConfig(rawConfig), [rawConfig]);
  const config = useMemo(() => uiConfig(resolvedConfig), [resolvedConfig]);
  const [state, dispatch] = useReducer(authStateReducer, INITIAL_AUTH_STATE);

  const report = useCallback(
    (event: AuthAnalyticsEvent) => {
      try {
        resolvedConfig.onAnalytics?.(event);
      } catch {
        // Analytics cannot change an authentication flow.
      }
    },
    [resolvedConfig]
  );

  const submit = useCallback(
    async (request: AuthRequest) => {
      dispatch({ type: "submit" });
      report({ name: "request", action: request.action });
      try {
        const result = await resolvedConfig.transport.execute(request);
        report({ name: "request", action: request.action, status: result.status });
        if (result.status === "authenticated") {
          await resolvedConfig.onAuthenticated?.(result.user);
          report({ name: "authenticated", status: result.status });
        } else if (result.status === "redirect_required") {
          await resolvedConfig.onRedirect?.(result.url, result.provider);
          report({ name: "redirect", status: result.status });
        }
        dispatch({ type: "result", result });
      } catch (error) {
        const message =
          resolvedConfig.mapError?.(error) ?? config.copy.genericError;
        dispatch({ type: "error", message });
        report({ name: "error", action: request.action });
      }
    },
    [config.copy.genericError, report, resolvedConfig]
  );

  const continueChallenge = useCallback(
    async (values: Readonly<Record<string, string>>) => {
      if (!state.challenge) return;
      await submit({
        action: "continue",
        continuationToken: state.challenge.continuationToken,
        kind: state.challenge.kind,
        values,
      });
    },
    [state.challenge, submit]
  );

  const resendVerification = useCallback(async () => {
    if (state.challenge?.kind !== "email_verification") return;
    await submit({
      action: "resend",
      continuationToken: state.challenge.continuationToken,
      kind: "email_verification",
    });
  }, [state.challenge, submit]);

  const usePasskey = useCallback(async () => {
    if (!state.challenge || !config.resolveWebAuthn) return;
    dispatch({ type: "submit" });
    try {
      await continueChallenge(await config.resolveWebAuthn(state.challenge));
    } catch (error) {
      dispatch({
        type: "error",
        message:
          resolvedConfig.mapError?.(error) ?? config.copy.genericError,
      });
    }
  }, [config, continueChallenge, resolvedConfig, state.challenge]);

  const useAlternativeChallenge = useCallback(() => {
    if (!state.challenge) return;
    const alternative = alternativeAuthChallenge(state.challenge);
    if (alternative) {
      dispatch({ type: "challenge", challenge: alternative });
    }
  }, [state.challenge]);

  const navigate = useCallback(
    (view: Exclude<AuthView, "challenge">) => {
      dispatch({ type: "navigate", view });
      report({ name: "view", view });
    },
    [report]
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      config,
      state,
      navigate,
      submit,
      continueChallenge,
      resendVerification,
      usePasskey,
      useAlternativeChallenge,
    }),
    [
      config,
      state,
      navigate,
      submit,
      continueChallenge,
      resendVerification,
      usePasskey,
      useAlternativeChallenge,
    ]
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used inside AuthProvider.");
  }
  return context;
}

export function challengeParameter(
  challenge: AuthClientChallenge,
  name: string
): string | undefined {
  const value = challenge.parameters?.[name];
  return typeof value === "string" ? value : undefined;
}
