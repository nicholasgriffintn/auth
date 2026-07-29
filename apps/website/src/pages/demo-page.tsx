import { ProviderDemo } from "../components/provider-demo";

export function DemoPage(): React.JSX.Element {
  const error = new URLSearchParams(window.location.search).get("error");

  return (
    <main className="demo-page section-shell">
      <header>
        <h1>Use the packages, not a simulation.</h1>
        <p>
          These sign-in buttons enter real OAuth flows through this site’s
          Cloudflare Worker. The Worker composes auth-core with each provider
          and supplies its own SQLite-backed storage adapters.
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
            <strong>The provider package owns protocol behaviour.</strong>
            State, PKCE and token exchange run through the same middleware a
            consuming service installs.
          </p>
          <p>
            <strong>The website owns application data.</strong>
            Users, external identities and sessions live in this Worker—not in
            a shared package.
          </p>
          <p>
            <strong>The browser receives an opaque session.</strong>
            Only hashed session and OAuth state values are persisted.
          </p>
        </div>
      </section>
    </main>
  );
}
