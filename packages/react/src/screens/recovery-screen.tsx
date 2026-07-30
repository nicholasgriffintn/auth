import { className } from '../config.js'
import { useAuth } from '../context.js'
import { DynamicAuthForm } from '../dynamic-form.js'
import type { AuthField } from '../types.js'

export function RecoveryScreen() {
  const { config, state, navigate, submit } = useAuth()
  const fields: readonly AuthField[] = [
    {
      name: 'email',
      label: config.signInFields.find((field) => field.name === 'email')?.label ?? 'Email',
      type: 'email',
      autoComplete: 'email',
      inputMode: 'email',
      required: true
    }
  ]

  return (
    <section aria-labelledby="auth-recovery-title" data-auth-screen="recovery">
      <h2 className={className(config, 'title')} id="auth-recovery-title">
        {config.copy.recoveryTitle}
      </h2>
      <DynamicAuthForm
        config={config}
        fields={fields}
        onSubmit={(values) =>
          submit({
            action: 'start_recovery',
            values: { email: String(values['email'] ?? '') }
          })
        }
        submitLabel={config.copy.recoverySubmit}
        submitting={state.submitting}
      />
      <button
        className={className(config, 'linkButton')}
        onClick={() => navigate('sign_in')}
        type="button"
      >
        {config.copy.signInTitle}
      </button>
    </section>
  )
}
