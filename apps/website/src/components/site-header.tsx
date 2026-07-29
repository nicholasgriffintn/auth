export function SiteHeader(): React.JSX.Element {
  return (
    <header className="site-header">
      <a className="brand" href="/" aria-label="Auth home">
        <img src="/auth-logo.png" alt="" width="46" height="46" />
        <span>Auth.</span>
      </a>
      <nav aria-label="Main navigation">
        <a href="/docs">Docs</a>
        <a href="/demo">Demo</a>
        <a href="https://github.com/nicholasgriffintn/auth">GitHub</a>
      </nav>
      <a className="button button-small" href="/docs/core">
        Get started
      </a>
    </header>
  );
}
