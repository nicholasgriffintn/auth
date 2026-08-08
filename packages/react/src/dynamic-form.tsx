import { Mail } from "lucide-react";
import { useId, useState, type FormEvent } from "react";

import { className } from "./config.js";
import {
  initialFormValues,
  selectFormValues,
} from "./form-values.js";
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
  magicLink = false,
  cancelLabel,
  onCancel,
}: {
  readonly config: ResolvedAuthUiConfig;
  readonly fields: readonly AuthField[];
  readonly submitLabel: string;
  readonly submitting: boolean;
  readonly onSubmit: (
    values: Readonly<Record<string, string | boolean>>
  ) => void | Promise<void>;
  readonly magicLink?: boolean;
  readonly cancelLabel?: string;
  readonly onCancel?: () => void;
}) {
  const formId = useId();
  const [values, setValues] = useState<Record<string, string | boolean>>(() =>
    initialFormValues(fields)
  );
  const [validationError, setValidationError] = useState<string>();

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submittedValues = selectFormValues(fields, values);
    for (const field of fields) {
      const value = submittedValues[field.name] ?? "";
      if (field.required && (value === "" || value === false)) {
        setValidationError(`${field.label} is required.`);
        return;
      }
      const error = field.validate?.(value, submittedValues);
      if (error) {
        setValidationError(error);
        return;
      }
    }
    setValidationError(undefined);
    await onSubmit(submittedValues);
  }

  return (
    <form
      className={className(config, "form")}
      data-auth-form=""
      onSubmit={handleSubmit}
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
            ) : type === "select" ? (
              <>
                <label className={className(config, "label")} htmlFor={id}>
                  {field.label}
                </label>
                <select
                  aria-describedby={field.description ? errorId : undefined}
                  autoFocus={index === 0}
                  className={className(config, "input")}
                  disabled={submitting}
                  id={id}
                  name={field.name}
                  onChange={(event) =>
                    setValues((current) => ({
                      ...current,
                      [field.name]: event.target.value,
                    }))
                  }
                  required={field.required}
                  value={String(values[field.name] ?? "")}
                >
                  <option value="">{field.placeholder ?? `Choose ${field.label}`}</option>
                  {field.options?.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </>
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
      {onCancel && cancelLabel ? (
        <div className={className(config, "actions")}>
          <button
            className={className(config, "linkButton")}
            disabled={submitting}
            onClick={onCancel}
            type="button"
          >
            {cancelLabel}
          </button>
          <button
            className={className(config, magicLink ? "magicLinkButton" : "button")}
            disabled={submitting}
            type="submit"
          >
            {magicLink ? (
              <>
                <Mail aria-hidden="true" size={16} />
                <span>{submitLabel}</span>
              </>
            ) : (
              submitLabel
            )}
          </button>
        </div>
      ) : (
        <button
          className={className(config, magicLink ? "magicLinkButton" : "button")}
          disabled={submitting}
          type="submit"
        >
          {magicLink ? (
            <>
              <Mail aria-hidden="true" size={16} />
              <span>{submitLabel}</span>
            </>
          ) : (
            submitLabel
          )}
        </button>
      )}
    </form>
  );
}
