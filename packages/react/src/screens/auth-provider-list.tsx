import { className } from '../config.js'
import { useAuth } from '../context.js'
import type { AuthProviderFieldPresentation } from '../types.js'
import { ExternalProviderControl } from './external-provider-control.js'

export function AuthProviderList({
  label = 'External sign-in providers',
  fieldPresentation = 'inline'
}: {
  readonly label?: string
  readonly fieldPresentation?: AuthProviderFieldPresentation
}) {
  const { config } = useAuth()
  if (config.providers.length === 0) return null

  return (
    <div aria-label={label} className={className(config, 'providerList')}>
      {config.providers.map((provider) => (
        <ExternalProviderControl
          fieldPresentation={fieldPresentation}
          key={provider.id}
          provider={provider}
        />
      ))}
    </div>
  )
}
