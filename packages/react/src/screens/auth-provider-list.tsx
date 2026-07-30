import { Fragment, useState } from 'react'

import { AppleDirectProviderControl } from '../apple-direct-provider.js'
import { className, combineClassNames } from '../config.js'
import { useAuth } from '../context.js'
import { DynamicAuthForm } from '../dynamic-form.js'
import { stringFormValues } from '../form-values.js'
import type { ExternalAuthProvider } from '../types.js'

export function AuthProviderList({
  label = 'External sign-in providers'
}: {
  readonly label?: string
}) {
  const { config } = useAuth()
  if (config.providers.length === 0) return null

  return (
    <div aria-label={label} className={className(config, 'providerList')}>
      {config.providers.map((provider) => (
        <ExternalProviderControl key={provider.id} provider={provider} />
      ))}
    </div>
  )
}

function ExternalProviderControl({
  provider
}: {
  readonly provider: ExternalAuthProvider
}) {
  const { config, state, submit } = useAuth()
  const [expanded, setExpanded] = useState(false)
  const fields = provider.fields ?? []

  if (provider.strategy === 'apple_direct') {
    return <AppleDirectProviderControl provider={provider} />
  }

  function startProvider(): void {
    if (fields.length > 0) {
      setExpanded((current) => !current)
      return
    }

    void submit({
      action: 'start_oauth',
      provider: provider.id,
      ...(provider.values ? { values: provider.values } : {})
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
          {provider.icon}
          <span>{provider.label}</span>
        </button>
        {expanded ? (
          <DynamicAuthForm
            config={config}
            fields={fields}
            onSubmit={(values) =>
              submit({
                action: 'start_oauth',
                provider: provider.id,
                values: {
                  ...stringFormValues(values),
                  ...provider.values
                }
              })
            }
            submitLabel={provider.submitLabel ?? config.copy.continueLabel}
            submitting={state.submitting}
          />
        ) : null}
      </div>
    </Fragment>
  )
}
