import { AuthError } from "@ngriffin_uk/auth-core";

export function requiredString(
  value: Readonly<Record<string, unknown>>,
  key: string,
  maxLength: number,
): string {
  const candidate = value[key];
  if (
    typeof candidate !== "string" ||
    candidate.length === 0 ||
    candidate.length > maxLength
  ) {
    throw new AuthError("invalid_input");
  }
  return candidate;
}

export function optionalString(
  value: Readonly<Record<string, unknown>>,
  key: string,
  maxLength: number,
): string | undefined {
  const candidate = value[key];
  if (candidate === undefined) return undefined;
  if (typeof candidate !== "string" || candidate.length > maxLength) {
    throw new AuthError("invalid_input");
  }
  return candidate;
}
