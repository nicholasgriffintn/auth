export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

export function isNonEmptyString(
  value: string | undefined
): value is string {
  return typeof value === 'string' && value.length > 0
}
