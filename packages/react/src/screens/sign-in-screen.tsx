import { className } from '../config.js'
import { useAuth } from '../context.js'
import { DynamicAuthForm } from '../dynamic-form.js'
import type { AuthField } from '../types.js'
import { AuthProviderList } from './auth-provider-list.js'

const DEFAULT_EMAIL_FIELD: AuthField = {
  name: 'email',
  label: 'Email',
  type: 'email',
  autoComplete: 'email',
  inputMode: 'email',
  required: true
}

export function SignInScreen() {
  const { config, state, navigate, submit } = useAuth()
  const descriptionId = config.copy.signInDescription
    ? 'auth-sign-in-description'
    : undefined
  const emailField =
    config.signInFields.find((field) => field.name === 'email') ?? DEFAULT_EMAIL_FIELD

  return (
    <section
      aria-describedby={descriptionId}
      aria-labelledby="auth-sign-in-title"
      className={className(config, 'signIn')}
      data-auth-screen="sign-in"
    >
      <header className={className(config, 'header')}>
        <h2 className={className(config, 'title')} id="auth-sign-in-title">
          {config.copy.signInTitle}
        </h2>
        {config.copy.signInDescription ? (
          <p className={className(config, 'description')} id={descriptionId}>
            {config.copy.signInDescription}
          </p>
        ) : null}
      </header>
      {config.capabilities.password ? (
        <DynamicAuthForm
          config={config}
          fields={config.signInFields}
          onSubmit={(values) => submit({ action: 'sign_in', values })}
          submitLabel={config.copy.signInSubmit}
          submitting={state.submitting}
        />
      ) : null}
      <AuthProviderList />
      {config.capabilities.magicLink ? (
        <DynamicAuthForm
          config={config}
          fields={[emailField]}
          onSubmit={(values) =>
            submit({
              action: 'request_magic_link',
              values: { email: String(values['email'] ?? '') }
            })
          }
          magicLink
          submitLabel={config.copy.magicLinkSubmit}
          submitting={state.submitting}
        />
      ) : null}
      {config.capabilities.recovery || config.capabilities.signUp ? (
        <div className={className(config, 'actions')}>
          {config.capabilities.recovery ? (
            <button
              className={className(config, 'linkButton')}
              onClick={() => navigate('forgot_password')}
              type="button"
            >
              {config.copy.recoveryTitle}
            </button>
          ) : null}
          {config.capabilities.signUp ? (
            <button
              className={className(config, 'linkButton')}
              onClick={() => navigate('sign_up')}
              type="button"
            >
              {config.copy.signUpTitle}
            </button>
          ) : null}
        </div>
      ) : null}
    </section>
  )
}
