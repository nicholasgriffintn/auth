import { SiteFooter } from "./components/site-footer";
import { SiteHeader } from "./components/site-header";
import { resolveRoute } from "./lib/routes";
import { DemoPage } from "./pages/demo-page";
import { DocPage } from "./pages/doc-page";
import { DocsIndexPage } from "./pages/docs-index-page";
import { HomePage } from "./pages/home-page";
import { NotFoundPage } from "./pages/not-found-page";

export function App(): React.JSX.Element {
  const route = resolveRoute(window.location.pathname);

  return (
    <div className="site">
      <SiteHeader />
      {route.name === "home" ? <HomePage /> : null}
      {route.name === "docs" ? <DocsIndexPage /> : null}
      {route.name === "doc" ? <DocPage url={route.url} /> : null}
      {route.name === "demo" ? <DemoPage /> : null}
      {route.name === "not-found" ? <NotFoundPage /> : null}
      <SiteFooter />
    </div>
  );
}
