import type { DemoOAuthProviderId } from "../lib/api";

const labels: Readonly<Record<DemoOAuthProviderId, string>> = {
  "amazon-cognito": "AWS",
  github: "GH",
};

export function ProviderIcon({
  provider,
}: {
  readonly provider: DemoOAuthProviderId;
}): React.JSX.Element {
  return (
    <span className={`provider-icon provider-icon-${provider}`} aria-hidden="true">
      {labels[provider]}
    </span>
  );
}
