import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { DocsNavigation } from "../components/docs-navigation";
import { docs } from "../generated/docs";

interface DocPageProps {
  readonly url: string;
}

export function DocPage({ url }: DocPageProps): React.JSX.Element {
  const entry = docs.find((candidate) => candidate.url === url);
  if (!entry) {
    return (
      <main className="simple-page">
        <h1>Documentation not found</h1>
        <p>That package is not part of this workspace.</p>
        <a className="button" href="/docs">
          Browse the reference
        </a>
      </main>
    );
  }

  return (
    <main className="docs-shell">
      <DocsNavigation currentUrl={entry.url} />
      <article className="markdown-page">
        <div className="markdown-meta">
          <span>{entry.kind === "provider" ? "Provider" : "Package"}</span>
          <a
            href={`https://github.com/nicholasgriffintn/auth/blob/main/${entry.source}`}
          >
            View source
          </a>
        </div>
        <Markdown remarkPlugins={[remarkGfm]}>{entry.markdown}</Markdown>
      </article>
    </main>
  );
}
