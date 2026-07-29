interface PackageMarkProps {
  readonly kind: "core" | "provider" | "service" | "ui";
  readonly label: string;
}

export function PackageMark({
  kind,
  label,
}: PackageMarkProps): React.JSX.Element {
  return (
    <span className={`package-mark package-mark-${kind}`}>
      <span aria-hidden="true">{markFor(kind)}</span>
      {label}
    </span>
  );
}

function markFor(kind: PackageMarkProps["kind"]): string {
  if (kind === "core") return "◫";
  if (kind === "provider") return "↗";
  if (kind === "service") return "◆";
  return "⌘";
}
