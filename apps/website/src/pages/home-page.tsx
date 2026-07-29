import { CodeCard } from "../components/code-card";
import { PackageMark } from "../components/package-mark";

export function HomePage(): React.JSX.Element {
  return (
    <main>
      <section className="hero section-shell">
        <div className="hero-copy">
          <h1>Simple. Extensible. Auth.</h1>
          <p>
            A focused TypeScript toolkit for sessions, challenge flows, OAuth,
            passkeys and MFA. Choose the capabilities you need. Keep your
            database, framework and user model.
          </p>
          <div className="button-row">
            <a className="button" href="/docs/core">
              Read the docs
            </a>
            <a className="text-link" href="/demo">
              Try live providers <span aria-hidden="true">↗</span>
            </a>
          </div>
        </div>
        <CodeCard />
      </section>

      <section className="numbers-strip" aria-label="Workspace summary">
        <div>
          <strong>12</strong>
          <span>focused packages</span>
        </div>
        <div>
          <strong>33</strong>
          <span>OAuth providers</span>
        </div>
        <div>
          <strong>0</strong>
          <span>database assumptions</span>
        </div>
      </section>

      <section className="section-shell composition-section">
        <div className="section-heading">
          <h2>One base. Only the auth you need.</h2>
          <p>
            Start with shared context and storage contracts, then layer in
            middleware. Each provider extends your configured instance with
            typed operations.
          </p>
        </div>
        <div className="architecture-map">
          <div className="map-service">
            <PackageMark kind="service" label="Your service" />
            <p>Routes, persistence, users and policy stay yours.</p>
          </div>
          <span className="map-arrow" aria-hidden="true">
            →
          </span>
          <div className="map-core">
            <PackageMark kind="core" label="auth-core" />
            <p>Configuration, context, sessions and challenge contracts.</p>
          </div>
          <span className="map-arrow" aria-hidden="true">
            →
          </span>
          <div className="map-providers">
            <PackageMark kind="provider" label="Middleware" />
            <div className="map-provider-list">
              <span>OAuth</span>
              <span>Password</span>
              <span>WebAuthn</span>
              <span>OTP</span>
            </div>
          </div>
        </div>
      </section>

      <section className="capability-section">
        <div className="section-shell">
          <div className="section-heading section-heading-light">
            <h2>The primitives are small. The flows are not.</h2>
            <p>
              Security-sensitive behaviour is implemented once and exposed
              through narrow, runtime-neutral packages.
            </p>
          </div>
          <div className="capability-grid">
            <Capability
              number="01"
              title="OAuth and OIDC"
              copy="State, PKCE, nonce, token exchange, refresh, revocation, discovery and verified ID tokens."
            />
            <Capability
              number="02"
              title="Challenge flows"
              copy="Opaque, single-use continuations for password reset, MFA, WebAuthn and provider-specific steps."
            />
            <Capability
              number="03"
              title="Service-owned data"
              copy="Storage contracts make persistence explicit. No bundled ORM, schema or hidden user table."
            />
            <Capability
              number="04"
              title="Configurable UI"
              copy="Unstyled React components cover password, OAuth, recovery, passkeys and multi-step challenges."
            />
          </div>
        </div>
      </section>

      <section className="section-shell provider-band">
        <div className="provider-band-copy">
          <h2>Providers are data, not architecture.</h2>
          <p>
            Install a maintained provider package, supply credentials and map the
            provider profile into your own identity model.
          </p>
          <a className="text-link" href="/docs#providers">
            Browse all 33 providers <span aria-hidden="true">→</span>
          </a>
        </div>
        <div className="provider-cloud" aria-label="Example providers">
          {[
            "GitHub",
            "Google",
            "Discord",
            "Apple",
            "Cognito",
            "GitLab",
            "Slack",
            "Spotify",
          ].map((provider) => (
            <span key={provider}>{provider}</span>
          ))}
        </div>
      </section>

      <section className="section-shell closing-section">
        <PackageMark kind="ui" label="Build your auth boundary once" />
        <h2>Bring your model. Get a typed auth layer</h2>
        <div className="button-row">
          <a className="button" href="/docs">
            Explore every package
          </a>
          <a className="text-link" href="/demo">
            Open the integration demo
          </a>
        </div>
      </section>
    </main>
  );
}

function Capability({
  copy,
  number,
  title,
}: {
  readonly copy: string;
  readonly number: string;
  readonly title: string;
}): React.JSX.Element {
  return (
    <article>
      <span>{number}</span>
      <h3>{title}</h3>
      <p>{copy}</p>
    </article>
  );
}
