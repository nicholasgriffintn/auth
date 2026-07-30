import { className } from "./config.js";
import { useAuth } from "./context.js";
import {
  ChallengeScreen,
  RecoveryScreen,
  RecoveryCodesScreen,
  SignInScreen,
  SignUpScreen,
} from "./screens.js";

export function AuthFlow({ className: customClassName }: { readonly className?: string }) {
  const { config, state } = useAuth();
  return (
    <div
      aria-busy={state.submitting}
      className={customClassName ?? className(config, "panel")}
      data-auth-view={state.view}
    >
      <AuthFeedback />
      {state.view === "sign_in" ? (
        <SignInScreen />
      ) : state.view === "sign_up" ? (
        <SignUpScreen />
      ) : state.view === "forgot_password" ? (
        <RecoveryScreen />
      ) : state.view === "recovery_codes" ? (
        <RecoveryCodesScreen />
      ) : (
        <ChallengeScreen />
      )}
    </div>
  );
}

export function AuthFeedback() {
  const { config, state } = useAuth();
  return (
    <>
      {state.error ? (
        <div className={className(config, "error")} role="alert">
          {state.error}
        </div>
      ) : null}
      {state.status ? (
        <div
          aria-live="polite"
          className={className(config, "status")}
          role="status"
        >
          {state.status}
        </div>
      ) : null}
    </>
  );
}
