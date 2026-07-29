const example = `const auth = createAuth({
  users,
  sessions,
  identities,
});

const appAuth = auth.use(
  createGitHubAuth({
    clientId,
    clientSecret,
    stateStore,
    resolveIdentity,
  }),
);`;

export function CodeCard(): React.JSX.Element {
  return (
    <div className="code-card" aria-label="Auth configuration example">
      <div className="code-card-header">
        <span>auth.ts</span>
        <span>service-owned</span>
      </div>
      <pre>
        <code>{example}</code>
      </pre>
      <div className="code-card-note">
        <span className="pulse" aria-hidden="true" />
        No hidden database or framework.
      </div>
    </div>
  );
}
