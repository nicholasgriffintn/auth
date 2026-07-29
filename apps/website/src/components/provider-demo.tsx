import { useEffect, useState } from "react";

import {
  getDemoProviders,
  getDemoSession,
  signOutDemo,
  type DemoProvider,
  type DemoUser,
} from "../lib/api";

const providerDescriptions: Readonly<Record<DemoProvider["id"], string>> = {
  discord: "PKCE, state and Discord profile resolution.",
  github: "OAuth state and GitHub identity resolution.",
  google: "PKCE, state and Google profile resolution.",
};

export function ProviderDemo(): React.JSX.Element {
  const [providers, setProviders] = useState<readonly DemoProvider[]>([]);
  const [user, setUser] = useState<DemoUser | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "error">(
    "loading",
  );

  useEffect(() => {
    let active = true;
    void Promise.all([getDemoProviders(), getDemoSession()])
      .then(([nextProviders, nextUser]) => {
        if (!active) return;
        setProviders(nextProviders);
        setUser(nextUser);
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
  if (user) {
    return <AuthenticatedDemo user={user} onSignOut={() => setUser(null)} />;
  }

  return (
    <div className="provider-grid">
      {providers.map((provider) => (
        <article className="provider-card" key={provider.id}>
          <ProviderIcon provider={provider.id} />
          <div>
            <h3>{provider.label}</h3>
            <p>{providerDescriptions[provider.id]}</p>
          </div>
          {provider.configured ? (
            <a
              className="button button-dark"
              href={`/api/oauth/${provider.id}/start`}
            >
              Continue with {provider.label}
            </a>
          ) : (
            <span className="provider-unavailable">Credentials not configured</span>
          )}
        </article>
      ))}
    </div>
  );
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

function ProviderIcon({
  provider,
}: {
  readonly provider: DemoProvider["id"];
}): React.JSX.Element {
  const labels = { discord: "D", github: "GH", google: "G" } as const;
  return (
    <span className={`provider-icon provider-icon-${provider}`} aria-hidden="true">
      {labels[provider]}
    </span>
  );
}
