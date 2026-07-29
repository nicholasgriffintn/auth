export function SiteFooter(): React.JSX.Element {
  return (
    <footer className="site-footer">
      <a className="brand brand-small" href="/">
        <img src="/auth-logo.png" alt="" width="34" height="34" />
        <span>Auth.</span>
      </a>
      <p>Composable authentication packages for TypeScript services.</p>
      <p>
        Built by{" "}
        <a href="https://nicholasgriffin.dev">Nicholas Griffin</a>.
      </p>
    </footer>
  );
}
