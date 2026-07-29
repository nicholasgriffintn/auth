export function encodeFormComponent(value: string): string {
  const parameters = new URLSearchParams({ value });
  return parameters.toString().slice("value=".length);
}
