export type SiteRoute =
  | { readonly name: "home" }
  | { readonly name: "docs" }
  | { readonly name: "doc"; readonly url: string }
  | { readonly name: "demo" }
  | { readonly name: "not-found" };

export function resolveRoute(pathname: string): SiteRoute {
  const path = normalisePath(pathname);
  if (path === "/") return { name: "home" };
  if (path === "/docs") return { name: "docs" };
  if (path === "/demo") return { name: "demo" };
  if (path.startsWith("/docs/")) return { name: "doc", url: path };
  return { name: "not-found" };
}

function normalisePath(pathname: string): string {
  if (!pathname.startsWith("/")) return "/";
  if (pathname === "/") return pathname;
  return pathname.replace(/\/+$/u, "");
}
