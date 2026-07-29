import { ProviderDemo } from "../components/provider-demo";

export function DemoPage(): React.JSX.Element {
  const error = new URLSearchParams(window.location.search).get("error");

  return (
    <main className="demo-page section-shell">
      <header>
        <h1>Use the packages, not a simulation.</h1>
        <p>
          The auth-react components below enter real password and OAuth flows
          through this site’s Cloudflare Worker. The Worker composes auth-core
          with each capability, including TOTP and WebAuthn enrolment, and
          supplies its own SQLite-backed storage adapters.
          Once configured, those factors are enforced after sign-out.
        </p>
      </header>
      {error ? (
        <p className="demo-error" role="alert">
          The provider could not complete this sign-in. Please try again.
        </p>
      ) : null}
      <ProviderDemo />
      <section className="demo-explanation">
        <h2>What this proves</h2>
        <div>
          <p>
            <strong>The package owns authentication behaviour.</strong>
            Password hashing, state, PKCE, token exchange and MFA ceremonies
            run through the same middleware a consuming service installs.
          </p>
          <p>
            <strong>The website owns application data.</strong>
            Users, password hashes, external identities and sessions live in
            this Worker—not in a shared package.
          </p>
          <p>
            <strong>The browser receives an opaque session.</strong>
            Session tokens are hashed. TOTP secrets and challenge payloads are
            encrypted before persistence.
          </p>
        </div>
      </section>
    </main>
  );
}
