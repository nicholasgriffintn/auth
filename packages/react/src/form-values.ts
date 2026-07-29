import type { AuthField } from "./types.js";

export type AuthFormValues = Readonly<Record<string, string | boolean>>;

export function initialFormValues(
  fields: readonly AuthField[]
): Record<string, string | boolean> {
  return Object.fromEntries(
    fields.map((field) => [
      field.name,
      field.initialValue ?? defaultFieldValue(field),
    ])
  );
}

export function selectFormValues(
  fields: readonly AuthField[],
  values: AuthFormValues
): Record<string, string | boolean> {
  return Object.fromEntries(
    fields.map((field) => [
      field.name,
      values[field.name] ??
        field.initialValue ??
        defaultFieldValue(field),
    ])
  );
}

function defaultFieldValue(field: AuthField): string | boolean {
  return field.type === "checkbox" ? false : "";
}

export function stringFormValues(
  values: AuthFormValues,
  omitted: readonly string[] = []
): Readonly<Record<string, string>> {
  return Object.fromEntries(
    Object.entries(values)
      .filter(([key]) => !omitted.includes(key))
      .map(([key, value]) => [key, String(value)])
  );
}
