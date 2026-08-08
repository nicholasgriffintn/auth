import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useReducer,
  useRef,
  useState,
  type ReactNode,
} from "react";

import {
  resolveConfig,
  uiConfig,
} from "./config.js";
import { followBrowserAuthRedirect } from "./browser-transport.js";
import {
  alternativeAuthChallenge,
  challengeStringParameters,
} from "./challenge.js";
import {
  authStateReducer,
  createInitialAuthState,
  type AuthState,
} from "./state.js";
import type {
  AuthAnalyticsEvent,
  AuthProviderConfig,
  AuthRequest,
  ResolvedAuthUiConfig,
  AuthView,
} from "./types.js";

export interface AuthContextValue {
  readonly config: ResolvedAuthUiConfig;
  readonly state: AuthState;
  readonly navigate: (
    view: Exclude<AuthView, "challenge" | "recovery_codes">
  ) => void;
  readonly submit: (request: AuthRequest) => Promise<void>;
  readonly continueChallenge: (
    values: Readonly<Record<string, string>>
  ) => Promise<void>;
  readonly resendVerification: () => Promise<void>;
  readonly usePasskey: () => Promise<void>;
  readonly useAlternativeChallenge: () => void;
  readonly recoveryCodes: readonly string[];
  readonly completeRecoveryCodes: () => Promise<void>;
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
  const [state, dispatch] = useReducer(
    authStateReducer,
    rawConfig.initialError,
    createInitialAuthState
  );
  const [recoveryCodes, setRecoveryCodes] = useState<readonly string[]>([]);
  const pendingUser = useRef<User | undefined>(undefined);
  const requestInFlight = useRef(false);

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
      if (requestInFlight.current) return;
      requestInFlight.current = true;
      const provider =
        "provider" in request ? { provider: request.provider } : {};
      dispatch({ type: "submit" });
      report({ name: "request", action: request.action, ...provider });
      try {
        const result = await resolvedConfig.transport.execute(request);
        report({
          name: "request",
          action: request.action,
          status: result.status,
          ...provider,
        });
        if (result.status === "authenticated") {
          if (result.recoveryCodes?.length) {
            pendingUser.current = result.user;
            setRecoveryCodes(result.recoveryCodes);
          } else {
            await resolvedConfig.onAuthenticated?.(result.user);
            report({ name: "authenticated", status: result.status });
          }
        } else if (result.status === "redirect_required") {
          if (resolvedConfig.onRedirect) {
            await resolvedConfig.onRedirect(result.url, result.provider);
          } else {
            followBrowserAuthRedirect(result.url);
          }
          report({ name: "redirect", status: result.status });
        }
        if (result.status !== "redirect_required") {
          requestInFlight.current = false;
        }
        dispatch({ type: "result", result });
      } catch (error) {
        requestInFlight.current = false;
        const message =
          resolvedConfig.mapError?.(error) ?? config.copy.genericError;
        dispatch({ type: "error", message });
        report({ name: "error", action: request.action, ...provider });
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
        values: {
          ...challengeStringParameters(state.challenge),
          ...values,
        },
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
    (view: Exclude<AuthView, "challenge" | "recovery_codes">) => {
      dispatch({ type: "navigate", view });
      report({ name: "view", view });
    },
    [report]
  );

  const completeRecoveryCodes = useCallback(async () => {
    dispatch({ type: "submit" });
    try {
      await resolvedConfig.onAuthenticated?.(pendingUser.current);
      pendingUser.current = undefined;
      setRecoveryCodes([]);
      report({ name: "authenticated", status: "authenticated" });
      dispatch({ type: "result", result: { status: "authenticated" } });
    } catch (error) {
      dispatch({
        type: "error",
        message:
          resolvedConfig.mapError?.(error) ?? config.copy.genericError,
      });
    }
  }, [config.copy.genericError, report, resolvedConfig]);

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
      recoveryCodes,
      completeRecoveryCodes,
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
      recoveryCodes,
      completeRecoveryCodes,
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
