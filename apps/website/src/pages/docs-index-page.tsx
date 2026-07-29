import { DocsNavigation } from "../components/docs-navigation";
import { docs } from "../generated/docs";

export function DocsIndexPage(): React.JSX.Element {
  const packages = docs.filter((entry) => entry.kind === "package");
  const providers = docs.filter((entry) => entry.kind === "provider");

  return (
    <main className="docs-shell">
      <DocsNavigation />
      <div className="docs-index">
        <header>
          <h1>Package reference</h1>
          <p>
            Each page is rendered from the README shipped beside its package.
            That keeps installation and API guidance aligned with the code that
            is published.
          </p>
        </header>
        <DocCollection
          title="Packages"
          copy="Compose the backend, primitives and frontend pieces you need."
          entries={packages}
        />
        <DocCollection
          id="providers"
          title="Providers"
          copy="OAuth definitions that install into the same central auth instance."
          entries={providers}
        />
      </div>
    </main>
  );
}

function DocCollection({
  copy,
  entries,
  id,
  title,
}: {
  readonly copy: string;
  readonly entries: readonly (typeof docs)[number][];
  readonly id?: string;
  readonly title: string;
}): React.JSX.Element {
  return (
    <section className="doc-collection" id={id}>
      <div>
        <h2>{title}</h2>
        <p>{copy}</p>
      </div>
      <div className="doc-card-grid">
        {entries.map((entry) => (
          <a href={entry.url} className="doc-card" key={entry.url}>
            <span>{entry.shortName}</span>
            <p>{entry.description}</p>
            <strong aria-hidden="true">→</strong>
          </a>
        ))}
      </div>
    </section>
  );
}
