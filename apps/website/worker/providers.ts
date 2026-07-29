import type { DemoProviderId, Env } from "./types";

type ProviderEnvironment = Pick<
  Env,
  | "COGNITO_CLIENT_ID"
  | "COGNITO_CLIENT_SECRET"
  | "COGNITO_DOMAIN"
  | "GITHUB_CLIENT_ID"
  | "GITHUB_CLIENT_SECRET"
>;

export interface ProviderSummary {
  readonly id: DemoProviderId;
  readonly label: string;
  readonly configured: boolean;
}

export function providerSummaries(
  env: ProviderEnvironment,
): readonly ProviderSummary[] {
  return [
    {
      id: "github",
      label: "GitHub",
      configured: Boolean(
        env.GITHUB_CLIENT_ID?.trim() && env.GITHUB_CLIENT_SECRET?.trim(),
      ),
    },
    {
      id: "password",
      label: "Self-rolled auth",
      configured: true,
    },
    {
      id: "amazon-cognito",
      label: "Amazon Cognito",
      configured: Boolean(
        env.COGNITO_DOMAIN?.trim() &&
          env.COGNITO_CLIENT_ID?.trim() &&
          env.COGNITO_CLIENT_SECRET?.trim(),
      ),
    },
  ];
}
