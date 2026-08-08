import { KeySquare } from 'lucide-react'

import { AppleDirectProviderControl } from '../apple-direct-provider.js'
import { className } from '../config.js'
import { useAuth } from '../context.js'
import type { AuthProviderFieldPresentation } from '../types.js'
import { ExternalProviderControl } from './external-provider-control.js'

export function AuthProviderList({
  label = 'Sign-in providers',
  fieldPresentation = 'inline'
}: {
  readonly label?: string
  readonly fieldPresentation?: AuthProviderFieldPresentation
}) {
  const { config, state, submit } = useAuth()
  const appleProvider = config.providers.find(
    (provider) => provider.strategy === 'apple_direct'
  )

  if (config.providers.length === 0 && !config.capabilities.passkeys) return null

  return (
    <>
      <div aria-label={label} className={className(config, 'providerList')}>
        {config.providers.map((provider) =>
          provider === appleProvider ? null : (
            <ExternalProviderControl
              fieldPresentation={fieldPresentation}
              key={provider.id}
              provider={provider}
            />
          )
        )}
        {config.capabilities.passkeys ? (
          <button
            className={className(config, 'passkeyButton')}
            disabled={state.submitting}
            onClick={() => void submit({ action: 'start_passkey', values: {} })}
            type="button"
          >
            <KeySquare aria-hidden="true" size={16} />
            <span>{config.copy.passkeyLabel}</span>
          </button>
        ) : null}
        {appleProvider ? <AppleDirectProviderControl provider={appleProvider} /> : null}
      </div>
      {config.capabilities.magicLink ? (
        <div className={className(config, 'separator')}>{config.copy.signInSeparator}</div>
      ) : null}
    </>
  )
}
