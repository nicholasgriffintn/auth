import {
  useId,
  useState,
  type FormEvent,
} from "react";

import { className } from "./config.js";
import type {
  AuthField,
  ResolvedAuthUiConfig,
} from "./types.js";

export function DynamicAuthForm({
  config,
  fields,
  submitLabel,
  submitting,
  onSubmit,
}: {
  readonly config: ResolvedAuthUiConfig;
  readonly fields: readonly AuthField[];
  readonly submitLabel: string;
  readonly submitting: boolean;
  readonly onSubmit: (
    values: Readonly<Record<string, string | boolean>>
  ) => void | Promise<void>;
}) {
  const formId = useId();
  const [values, setValues] = useState<Record<string, string | boolean>>(() =>
    Object.fromEntries(
      fields.map((field) => [field.name, field.initialValue ?? ""])
    )
  );
  const [validationError, setValidationError] = useState<string>();

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    for (const field of fields) {
      const value = values[field.name] ?? "";
      if (field.required && (value === "" || value === false)) {
        setValidationError(`${field.label} is required.`);
        return;
      }
      const error = field.validate?.(value, values);
      if (error) {
        setValidationError(error);
        return;
      }
    }
    setValidationError(undefined);
    await onSubmit(values);
  }

  return (
    <form
      className={className(config, "form")}
      data-auth-form=""
      onSubmit={handleSubmit}
      noValidate
    >
      {fields.map((field, index) => {
        const id = `${formId}-${field.name}`;
        const errorId = `${id}-description`;
        const type = field.type ?? "text";
        return (
          <div className={className(config, "field")} key={field.name}>
            {type === "checkbox" ? (
              <label className={className(config, "label")} htmlFor={id}>
                <input
                  checked={values[field.name] === true}
                  className={className(config, "input")}
                  disabled={submitting}
                  id={id}
                  name={field.name}
                  onChange={(event) =>
                    setValues((current) => ({
                      ...current,
                      [field.name]: event.target.checked,
                    }))
                  }
                  required={field.required}
                  type="checkbox"
                />
                {field.label}
              </label>
            ) : (
              <>
                <label className={className(config, "label")} htmlFor={id}>
                  {field.label}
                </label>
                <input
                  aria-describedby={field.description ? errorId : undefined}
                  autoComplete={field.autoComplete}
                  autoFocus={index === 0}
                  className={className(config, "input")}
                  disabled={submitting}
                  id={id}
                  inputMode={field.inputMode}
                  maxLength={field.maxLength}
                  minLength={field.minLength}
                  name={field.name}
                  onChange={(event) =>
                    setValues((current) => ({
                      ...current,
                      [field.name]: event.target.value,
                    }))
                  }
                  pattern={field.pattern}
                  placeholder={field.placeholder}
                  required={field.required}
                  type={type}
                  value={String(values[field.name] ?? "")}
                />
              </>
            )}
            {field.description ? (
              <div
                className={className(config, "description")}
                id={errorId}
              >
                {field.description}
              </div>
            ) : null}
          </div>
        );
      })}
      {validationError ? (
        <div className={className(config, "error")} role="alert">
          {validationError}
        </div>
      ) : null}
      <button
        className={className(config, "button")}
        disabled={submitting}
        type="submit"
      >
        {submitLabel}
      </button>
    </form>
  );
}
