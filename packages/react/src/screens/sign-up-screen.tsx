import { className } from '../config.js'
import { useAuth } from '../context.js'
import { DynamicAuthForm } from '../dynamic-form.js'

export function SignUpScreen() {
  const { config, state, navigate, submit } = useAuth()

  return (
    <section aria-labelledby="auth-sign-up-title" data-auth-screen="sign-up">
      <h2 className={className(config, 'title')} id="auth-sign-up-title">
        {config.copy.signUpTitle}
      </h2>
      <DynamicAuthForm
        config={config}
        fields={config.signUpFields}
        onSubmit={(values) => submit({ action: 'sign_up', values })}
        submitLabel={config.copy.signUpSubmit}
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
