import { className } from "./config.js";
import {
  challengeParameter,
  useAuth,
} from "./context.js";
import { DynamicAuthForm } from "./dynamic-form.js";
import type {
  AuthClientChallenge,
  AuthField,
} from "./types.js";

export function SignInScreen() {
  const { config, state, navigate, submit } = useAuth();
  return (
    <section aria-labelledby="auth-sign-in-title" data-auth-screen="sign-in">
      <h1 className={className(config, "title")} id="auth-sign-in-title">
        {config.copy.signInTitle}
      </h1>
      {config.capabilities.password ? (
        <DynamicAuthForm
          config={config}
          fields={config.signInFields}
          onSubmit={(values) => submit({ action: "sign_in", values })}
          submitLabel={config.copy.signInSubmit}
          submitting={state.submitting}
        />
      ) : null}
      {config.providers.length > 0 ? (
        <div
          aria-label="External sign-in providers"
          className={className(config, "providerList")}
        >
          {config.providers.map((provider) => (
            <button
              className={className(config, "providerButton")}
              data-auth-provider={provider.id}
              disabled={state.submitting}
              key={provider.id}
              onClick={() =>
                void submit({ action: "start_oauth", provider: provider.id })
              }
              type="button"
            >
              {config.renderProviderIcon?.(provider) ?? provider.icon}
              <span>{provider.label}</span>
            </button>
          ))}
        </div>
      ) : null}
      {config.capabilities.passkeys ? (
        <button
          className={className(config, "button")}
          disabled={state.submitting}
          onClick={() => void submit({ action: "start_passkey", values: {} })}
          type="button"
        >
          {config.copy.passkeyLabel}
        </button>
      ) : null}
      <div className={className(config, "actions")}>
        {config.capabilities.recovery ? (
          <button
            className={className(config, "linkButton")}
            onClick={() => navigate("forgot_password")}
            type="button"
          >
            {config.copy.recoveryTitle}
          </button>
        ) : null}
        {config.capabilities.signUp ? (
          <button
            className={className(config, "linkButton")}
            onClick={() => navigate("sign_up")}
            type="button"
          >
            {config.copy.signUpTitle}
          </button>
        ) : null}
      </div>
    </section>
  );
}

export function SignUpScreen() {
  const { config, state, navigate, submit } = useAuth();
  return (
    <section aria-labelledby="auth-sign-up-title" data-auth-screen="sign-up">
      <h1 className={className(config, "title")} id="auth-sign-up-title">
        {config.copy.signUpTitle}
      </h1>
      <DynamicAuthForm
        config={config}
        fields={config.signUpFields}
        onSubmit={(values) => submit({ action: "sign_up", values })}
        submitLabel={config.copy.signUpSubmit}
        submitting={state.submitting}
      />
      <button
        className={className(config, "linkButton")}
        onClick={() => navigate("sign_in")}
        type="button"
      >
        {config.copy.signInTitle}
      </button>
    </section>
  );
}

export function RecoveryScreen() {
  const { config, state, navigate, submit } = useAuth();
  const fields: readonly AuthField[] = [
    {
      name: "email",
      label: config.signInFields.find((field) => field.name === "email")?.label ?? "Email",
      type: "email",
      autoComplete: "email",
      inputMode: "email",
      required: true,
    },
  ];
  return (
    <section aria-labelledby="auth-recovery-title" data-auth-screen="recovery">
      <h1 className={className(config, "title")} id="auth-recovery-title">
        {config.copy.recoveryTitle}
      </h1>
      <DynamicAuthForm
        config={config}
        fields={fields}
        onSubmit={(values) =>
          submit({
            action: "start_recovery",
            values: { email: String(values["email"] ?? "") },
          })
        }
        submitLabel={config.copy.recoverySubmit}
        submitting={state.submitting}
      />
      <button
        className={className(config, "linkButton")}
        onClick={() => navigate("sign_in")}
        type="button"
      >
        {config.copy.signInTitle}
      </button>
    </section>
  );
}

export function ChallengeScreen() {
  const {
    config,
    state,
    continueChallenge,
    resendVerification,
    usePasskey,
  } = useAuth();
  const challenge = state.challenge;
  if (!challenge) return null;

  const title = challengeTitle(challenge, config.copy);
  return (
    <section
      aria-labelledby="auth-challenge-title"
      className={className(config, "challenge")}
      data-auth-challenge={challenge.kind}
    >
      <h1 className={className(config, "title")} id="auth-challenge-title">
        {title}
      </h1>
      {challenge.kind === "mfa_selection" ? (
        <ChallengeSelection challenge={challenge} />
      ) : challenge.kind === "webauthn" ? (
        config.resolveWebAuthn ? (
          <button
            className={className(config, "button")}
            disabled={state.submitting}
            onClick={() => void usePasskey()}
            type="button"
          >
            {config.copy.passkeyLabel}
          </button>
        ) : (
          <UnsupportedChallenge challenge={challenge} />
        )
      ) : challenge.kind === "unsupported" ? (
        <UnsupportedChallenge challenge={challenge} />
      ) : challenge.kind === "mfa_setup" &&
        !challengeParameter(challenge, "secret") ? (
        <button
          className={className(config, "button")}
          disabled={state.submitting}
          onClick={() => void continueChallenge({ setup: "start" })}
          type="button"
        >
          {config.copy.continueLabel}
        </button>
      ) : (
        <>
          {challenge.kind === "mfa_setup" ? (
            <TotpSetup challenge={challenge} />
          ) : null}
          <DynamicAuthForm
            config={config}
            fields={challengeFields(challenge, config.copy)}
            onSubmit={(values) =>
              continueChallenge(stringValues(values, ["confirmPassword"]))
            }
            submitLabel={
              challenge.kind === "password" ||
              challenge.kind === "new_password" ||
              challenge.kind === "password_reset"
                ? config.copy.continueLabel
                : config.copy.codeSubmit
            }
            submitting={state.submitting}
          />
          {challenge.kind === "email_verification" ? (
            <button
              className={className(config, "linkButton")}
              disabled={state.submitting}
              onClick={() => void resendVerification()}
              type="button"
            >
              {config.copy.resendLabel}
            </button>
          ) : null}
        </>
      )}
    </section>
  );
}

function ChallengeSelection({
  challenge,
}: {
  readonly challenge: AuthClientChallenge;
}) {
  const { config, state, continueChallenge } = useAuth();
  const available = challenge.parameters?.["availableChallenges"];
  const choices = Array.isArray(available) ? available : [];
  return (
    <div className={className(config, "actions")}>
      {choices.map((choice) => (
        <button
          className={className(config, "button")}
          disabled={state.submitting}
          key={choice}
          onClick={() => void continueChallenge({ challenge: choice })}
          type="button"
        >
          {choice.replaceAll("_", " ").toLowerCase()}
        </button>
      ))}
    </div>
  );
}

function TotpSetup({
  challenge,
}: {
  readonly challenge: AuthClientChallenge;
}) {
  const { config } = useAuth();
  const secret = challengeParameter(challenge, "secret");
  const uri = challengeParameter(challenge, "uri");
  return (
    <div data-auth-totp-setup="">
      {uri ? config.renderTotpQrCode?.(uri) : null}
      {secret ? (
        <p className={className(config, "description")}>
          <span>Manual setup code: </span>
          <code>{secret}</code>
        </p>
      ) : null}
    </div>
  );
}

function UnsupportedChallenge({
  challenge,
}: {
  readonly challenge: AuthClientChallenge;
}) {
  const { config } = useAuth();
  return (
    config.renderUnsupportedChallenge?.(challenge) ?? (
      <p className={className(config, "error")} role="alert">
        {config.copy.unsupportedChallenge}
      </p>
    )
  );
}

function challengeFields(
  challenge: AuthClientChallenge,
  copy: {
    readonly codeLabel: string;
    readonly passwordLabel: string;
    readonly newPasswordLabel: string;
    readonly confirmPasswordLabel: string;
  }
): readonly AuthField[] {
  if (challenge.kind === "password") {
    return [
      {
        name: "password",
        label: copy.passwordLabel,
        type: "password",
        autoComplete: "current-password",
        required: true,
      },
    ];
  }
  if (challenge.kind === "new_password") {
    return passwordFields(copy, false);
  }
  if (challenge.kind === "password_reset") {
    return [
      codeField(copy.codeLabel),
      ...passwordFields(copy, false),
    ];
  }
  if (challenge.kind === "custom") {
    return [
      {
        name: "answer",
        label: challengeParameter(challenge, "prompt") ?? copy.codeLabel,
        required: true,
      },
    ];
  }
  return [codeField(copy.codeLabel)];
}

function passwordFields(
  copy: {
    readonly newPasswordLabel: string;
    readonly confirmPasswordLabel: string;
  },
  includeCurrent: boolean
): readonly AuthField[] {
  return [
    ...(includeCurrent
      ? [
          {
            name: "currentPassword",
            label: "Current password",
            type: "password" as const,
            required: true,
          },
        ]
      : []),
    {
      name: "newPassword",
      label: copy.newPasswordLabel,
      type: "password",
      autoComplete: "new-password",
      required: true,
      minLength: 8,
    },
    {
      name: "confirmPassword",
      label: copy.confirmPasswordLabel,
      type: "password",
      autoComplete: "new-password",
      required: true,
      validate(value, values) {
        return value === values["newPassword"]
          ? null
          : "Passwords do not match.";
      },
    },
  ];
}

function codeField(label: string): AuthField {
  return {
    name: "code",
    label,
    autoComplete: "one-time-code",
    inputMode: "numeric",
    required: true,
    minLength: 4,
    maxLength: 2048,
  };
}

function challengeTitle(
  challenge: AuthClientChallenge,
  copy: {
    readonly recoveryTitle: string;
    readonly codeLabel: string;
    readonly newPasswordLabel: string;
    readonly passkeyLabel: string;
  }
): string {
  switch (challenge.kind) {
    case "password_reset":
      return copy.recoveryTitle;
    case "new_password":
      return copy.newPasswordLabel;
    case "webauthn":
      return copy.passkeyLabel;
    case "mfa_selection":
      return "Choose a verification method";
    case "mfa_setup":
      return "Set up an authenticator";
    default:
      return copy.codeLabel;
  }
}

function stringValues(
  values: Readonly<Record<string, string | boolean>>,
  omitted: readonly string[]
): Readonly<Record<string, string>> {
  return Object.fromEntries(
    Object.entries(values)
      .filter(([key]) => !omitted.includes(key))
      .map(([key, value]) => [key, String(value)])
  );
}
