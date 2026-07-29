import { useMemo, useState } from "react";

import { docs, type DocEntry } from "../generated/docs";

interface DocsNavigationProps {
  readonly currentUrl?: string;
}

export function DocsNavigation({
  currentUrl,
}: DocsNavigationProps): React.JSX.Element {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => filterDocs(docs, query), [query]);
  const packages = filtered.filter((entry) => entry.kind === "package");
  const providers = filtered.filter((entry) => entry.kind === "provider");

  return (
    <aside className="docs-navigation">
      <label>
        <span className="visually-hidden">Search documentation</span>
        <input
          type="search"
          value={query}
          onChange={(event) => setQuery(event.currentTarget.value)}
          placeholder="Find a package"
        />
      </label>
      <DocsGroup
        title="Packages"
        entries={packages}
        {...(currentUrl ? { currentUrl } : {})}
      />
      <DocsGroup
        title="Providers"
        entries={providers}
        {...(currentUrl ? { currentUrl } : {})}
      />
    </aside>
  );
}

function DocsGroup({
  currentUrl,
  entries,
  title,
}: {
  readonly currentUrl?: string;
  readonly entries: readonly DocEntry[];
  readonly title: string;
}): React.JSX.Element {
  return (
    <section>
      <h2>{title}</h2>
      {entries.length ? (
        <ul>
          {entries.map((entry) => (
            <li key={entry.url}>
              <a
                href={entry.url}
                aria-current={entry.url === currentUrl ? "page" : undefined}
              >
                {entry.shortName}
              </a>
            </li>
          ))}
        </ul>
      ) : (
        <p className="docs-empty">No matches.</p>
      )}
    </section>
  );
}

function filterDocs(
  entries: readonly DocEntry[],
  query: string,
): readonly DocEntry[] {
  const normalised = query.trim().toLocaleLowerCase();
  if (!normalised) return entries;
  return entries.filter(
    (entry) =>
      entry.name.toLocaleLowerCase().includes(normalised) ||
      entry.description.toLocaleLowerCase().includes(normalised),
  );
}
