export function NotFoundPage(): React.JSX.Element {
  return (
    <main className="simple-page">
      <h1>This route has no auth flow.</h1>
      <p>The page you requested does not exist.</p>
      <a className="button" href="/">
        Return home
      </a>
    </main>
  );
}
