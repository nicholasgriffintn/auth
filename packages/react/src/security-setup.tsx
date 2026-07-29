import { AuthFeedback } from "./auth-flow.js";
import { className } from "./config.js";
import { useAuth } from "./context.js";
import { ChallengeScreen } from "./screens.js";

export interface AuthSecurityStatus {
  readonly totpConfigured: boolean;
  readonly passkeyCount: number;
}

export function AuthSecuritySetup({
  status,
}: {
  readonly status: AuthSecurityStatus;
}) {
  const { config, navigate, state, submit } = useAuth();

  if (state.view === "challenge") {
    return (
      <div
        aria-busy={state.submitting}
        className={className(config, "panel")}
        data-auth-security-setup=""
      >
        <AuthFeedback />
        <ChallengeScreen />
        <button
          className={className(config, "linkButton")}
          disabled={state.submitting}
          onClick={() => navigate("sign_in")}
          type="button"
        >
          {config.copy.cancelLabel}
        </button>
      </div>
    );
  }

  return (
    <section
      aria-labelledby="auth-security-title"
      className={className(config, "panel")}
      data-auth-security-setup=""
    >
      <h2 className={className(config, "title")} id="auth-security-title">
        {config.copy.securityTitle}
      </h2>
      <AuthFeedback />
      <div className={className(config, "securityList")}>
        <SecurityMethod
          action={() => submit({ action: "start_totp_setup" })}
          buttonLabel={
            status.totpConfigured
              ? config.copy.totpConfiguredLabel
              : config.copy.totpSetupLabel
          }
          description={config.copy.totpDescription}
          disabled={state.submitting || status.totpConfigured}
          title={config.copy.totpTitle}
        />
        <SecurityMethod
          action={() => submit({ action: "start_webauthn_registration" })}
          buttonLabel={config.copy.passkeySetupLabel}
          description={
            status.passkeyCount > 0
              ? `${config.copy.passkeyDescription} ${status.passkeyCount} configured.`
              : config.copy.passkeyDescription
          }
          disabled={state.submitting}
          title={config.copy.passkeyTitle}
        />
      </div>
    </section>
  );
}

function SecurityMethod({
  action,
  buttonLabel,
  description,
  disabled,
  title,
}: {
  readonly action: () => Promise<void>;
  readonly buttonLabel: string;
  readonly description: string;
  readonly disabled: boolean;
  readonly title: string;
}) {
  const { config } = useAuth();
  return (
    <article className={className(config, "securityItem")}>
      <div>
        <h3>{title}</h3>
        <p className={className(config, "description")}>{description}</p>
      </div>
      <button
        className={className(config, "button")}
        disabled={disabled}
        onClick={() => void action()}
        type="button"
      >
        {buttonLabel}
      </button>
    </article>
  );
}
