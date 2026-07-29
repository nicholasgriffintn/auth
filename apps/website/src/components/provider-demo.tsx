import { useEffect, useRef, useState } from "react";
import {
  AuthFlow,
  AuthProvider,
  AuthSecuritySetup,
  useAuth,
  type AuthField,
  type ExternalAuthProvider,
} from "@ngriffin_uk/auth-react";

import {
  getDemoProviders,
  getDemoSecurity,
  getDemoSession,
  signOutDemo,
  type DemoProvider,
  type DemoSecurityStatus,
  type DemoUser,
} from "../lib/api";
import { demoAuthTransport } from "../lib/demo-auth-transport";
import { resolveWebAuthnChallenge } from "../lib/webauthn";
import { ProviderIcon } from "./provider-icon";

const emailField: AuthField = {
  name: "email",
  label: "Email",
  type: "email",
  autoComplete: "username",
  inputMode: "email",
  required: true,
  maxLength: 320,
};

const passwordField: AuthField = {
  name: "password",
  label: "Password",
  type: "password",
  autoComplete: "current-password",
  required: true,
  maxLength: 1_024,
};

const signInFields: readonly AuthField[] = [emailField, passwordField];

const signUpFields: readonly AuthField[] = [
  {
    ...emailField,
    autoComplete: "email",
  },
  {
    ...passwordField,
    autoComplete: "new-password",
    minLength: 8,
    description: "Use a unique password. Demo accounts persist.",
  },
  {
    name: "confirmPassword",
    label: "Confirm password",
    type: "password",
    autoComplete: "new-password",
    required: true,
    minLength: 8,
    maxLength: 1_024,
    validate(value, values) {
      return value === values.password ? null : "Passwords do not match.";
    },
  },
];

export function ProviderDemo(): React.JSX.Element {
  const [providers, setProviders] = useState<readonly DemoProvider[]>([]);
  const [user, setUser] = useState<DemoUser | null>(null);
  const [security, setSecurity] = useState<DemoSecurityStatus | null>(null);
  const [pendingMfa, setPendingMfa] = useState(false);
  const [status, setStatus] = useState<"loading" | "ready" | "error">(
    "loading",
  );

  useEffect(() => {
    let active = true;
    void Promise.all([getDemoProviders(), getDemoSession()])
      .then(async ([nextProviders, session]) => {
        if (!active) return;
        setProviders(nextProviders);
        setUser(session.user);
        setPendingMfa(session.pendingMfa);
        if (session.user) {
          const nextSecurity = await getDemoSecurity();
          if (!active) return;
          setSecurity(nextSecurity);
        }
        setStatus("ready");
      })
      .catch(() => {
        if (active) setStatus("error");
      });
    return () => {
      active = false;
    };
  }, []);

  if (status === "loading") {
    return <p className="demo-status">Checking live provider configuration…</p>;
  }
  if (status === "error") {
    return (
      <p className="demo-status demo-status-error">
        The demo API is unavailable. The package documentation is still ready.
      </p>
    );
  }
  const externalProviders: readonly ExternalAuthProvider[] = providers.flatMap(
    (provider) =>
      provider.id === "password" || !provider.configured
        ? []
        : [
          {
            id: provider.id,
            label: `Continue with ${provider.label}`,
            icon: <ProviderIcon provider={provider.id} />,
          },
        ],
  );

  return (
    <AuthProvider<DemoUser>
      config={{
        transport: demoAuthTransport,
        capabilities: {
          password: true,
          passkeys: false,
          signUp: true,
          recovery: false,
          signOut: false,
        },
        providers: externalProviders,
        signInFields,
        signUpFields,
        copy: {
          signInTitle: "Sign into your demo account",
          signUpTitle: "Create a demo account",
          signUpSubmit: "Create demo account",
          securityTitle: "Protect your demo account",
        },
        mapError: (error) =>
          error instanceof Error
            ? error.message
            : "Authentication could not be completed.",
        onAuthenticated: async (nextUser) => {
          if (!nextUser) return;
          setUser(nextUser);
          setSecurity(await getDemoSecurity());
        },
        onRedirect: (url) => window.location.assign(url),
        renderTotpQrCode: (uri) => (
          <a className="text-link" href={uri}>
            Open in your authenticator app
          </a>
        ),
        resolveWebAuthn: resolveWebAuthnChallenge,
      }}
    >
      <ResumePendingMfa
        pending={pendingMfa}
        onResume={() => setPendingMfa(false)}
      />
      {user ? (
        <div className="demo-security-layout">
          <AuthenticatedDemo
            user={user}
            onSignOut={() => {
              setUser(null);
              setSecurity(null);
            }}
          />
          {security ? (
            <AuthSecuritySetup status={security} />
          ) : (
            <p className="demo-status">Loading security settings…</p>
          )}
        </div>
      ) : (
        <div className="demo-auth-layout">
          <AuthFlow className="demo-auth-panel" />
          <aside className="demo-auth-context">
            <h2>One component, five authentication paths.</h2>
            <p>
              This form is rendered by <code>@ngriffin_uk/auth-react</code>.
              Its transport sends password requests to the self-rolled backend
              and redirects GitHub or Cognito requests through their provider
              packages.
            </p>
            <p>
              Sign in to configure TOTP and WebAuthn with the same package UI.
              Use a test email and a unique password.
            </p>
          </aside>
        </div>
      )}
    </AuthProvider>
  );
}

function ResumePendingMfa({
  onResume,
  pending,
}: {
  readonly onResume: () => void;
  readonly pending: boolean;
}): null {
  const { submit } = useAuth();
  const started = useRef(false);

  useEffect(() => {
    if (!pending || started.current) return;
    started.current = true;
    onResume();
    void submit({ action: "resume_mfa" });
  }, [onResume, pending, submit]);

  return null;
}

function AuthenticatedDemo({
  onSignOut,
  user,
}: {
  readonly onSignOut: () => void;
  readonly user: DemoUser;
}): React.JSX.Element {
  const [busy, setBusy] = useState(false);

  async function signOut(): Promise<void> {
    setBusy(true);
    try {
      await signOutDemo();
      onSignOut();
    } finally {
      setBusy(false);
    }
  }

  return (
    <article className="session-card">
      {user.avatarUrl ? (
        <img src={user.avatarUrl} alt="" width="72" height="72" />
      ) : (
        <span className="session-avatar" aria-hidden="true">
          {user.displayName.slice(0, 1).toLocaleUpperCase()}
        </span>
      )}
      <div>
        <h3>{user.displayName}</h3>
        <p>{user.email}</p>
        <span>Authenticated with {user.provider}</span>
      </div>
      <button
        className="button button-dark"
        type="button"
        disabled={busy}
        onClick={() => void signOut()}
      >
        {busy ? "Signing out…" : "Sign out"}
      </button>
    </article>
  );
}
