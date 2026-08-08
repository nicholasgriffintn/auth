import { Fragment, useRef, useState } from 'react'
import { LogIn } from 'lucide-react'

import { className, combineClassNames } from '../config.js'
import { useAuth } from '../context.js'
import { DynamicAuthForm } from '../dynamic-form.js'
import { stringFormValues } from '../form-values.js'
import type { AuthProviderFieldPresentation, ExternalAuthProvider } from '../types.js'
import { ProviderFieldDialog } from './provider-field-dialog.js'

export function ExternalProviderControl({
  fieldPresentation,
  provider
}: {
  readonly fieldPresentation: AuthProviderFieldPresentation
  readonly provider: ExternalAuthProvider
}) {
  const { config, state, submit } = useAuth()
  const dialog = useRef<HTMLDialogElement>(null)
  const [expanded, setExpanded] = useState(false)
  const fields = provider.fields ?? []

  function startProvider(): void {
    if (fields.length === 0) {
      void submitProvider({})
      return
    }
    if (fieldPresentation === 'modal') {
      dialog.current?.showModal()
      setExpanded(true)
      return
    }
    setExpanded((current) => !current)
  }

  function submitProvider(values: Readonly<Record<string, string | boolean>>) {
    const requestValues = {
      ...stringFormValues(values),
      ...provider.values
    }
    return submit({
      action: 'start_oauth',
      provider: provider.id,
      ...(Object.keys(requestValues).length > 0 ? { values: requestValues } : {})
    })
  }

  return (
    <Fragment>
      {provider.separatorBefore ? (
        <div className={className(config, 'separator')}>{provider.separatorBefore}</div>
      ) : null}
      <div data-auth-provider={provider.id}>
        <button
          aria-expanded={fields.length > 0 ? expanded : undefined}
          className={combineClassNames(className(config, 'providerButton'), provider.className)}
          disabled={state.submitting}
          onClick={startProvider}
          type="button"
        >
          <LogIn aria-hidden="true" size={16} />
          <span>{provider.label}</span>
        </button>
        {fields.length > 0 && fieldPresentation === 'modal' ? (
          <ProviderFieldDialog
            dialog={dialog}
            onClose={() => setExpanded(false)}
            onSubmit={submitProvider}
            provider={provider}
          />
        ) : expanded ? (
          <DynamicAuthForm
            config={config}
            fields={fields}
            onSubmit={submitProvider}
            submitLabel={provider.submitLabel ?? config.copy.continueLabel}
            submitting={state.submitting}
          />
        ) : null}
      </div>
    </Fragment>
  )
}
