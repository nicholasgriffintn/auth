import { challengeParameter } from '../challenge.js'
import { className } from '../config.js'
import { useAuth } from '../context.js'
import { DynamicAuthForm } from '../dynamic-form.js'
import { stringFormValues } from '../form-values.js'
import {
  ChallengeSelection,
  TotpSetup,
  UnsupportedChallenge
} from './challenge-content.js'
import { challengeFields, challengeTitle } from './challenge-fields.js'

export function ChallengeScreen() {
  const {
    config,
    state,
    continueChallenge,
    resendVerification,
    useAlternativeChallenge,
    usePasskey
  } = useAuth()
  const challenge = state.challenge

  if (!challenge) return null

  return (
    <section
      aria-labelledby="auth-challenge-title"
      className={className(config, 'challenge')}
      data-auth-challenge={challenge.kind}
    >
      <h2 className={className(config, 'title')} id="auth-challenge-title">
        {challengeTitle(challenge, config.copy)}
      </h2>
      {challenge.kind === 'mfa_selection' ? (
        <ChallengeSelection challenge={challenge} />
      ) : challenge.kind === 'webauthn' ? (
        config.resolveWebAuthn ? (
          <div className={className(config, 'actions')}>
            <button
              className={className(config, 'button')}
              disabled={state.submitting}
              onClick={() => void usePasskey()}
              type="button"
            >
              {config.copy.passkeyLabel}
            </button>
            {challengeParameter(challenge, 'alternativeContinuationToken') ? (
              <button
                className={className(config, 'linkButton')}
                disabled={state.submitting}
                onClick={useAlternativeChallenge}
                type="button"
              >
                {config.copy.totpOrRecoveryLabel}
              </button>
            ) : null}
          </div>
        ) : (
          <UnsupportedChallenge challenge={challenge} />
        )
      ) : challenge.kind === 'unsupported' ? (
        <UnsupportedChallenge challenge={challenge} />
      ) : challenge.kind === 'mfa_setup' && !challengeParameter(challenge, 'secret') ? (
        <button
          className={className(config, 'button')}
          disabled={state.submitting}
          onClick={() => void continueChallenge({ setup: 'start' })}
          type="button"
        >
          {config.copy.continueLabel}
        </button>
      ) : (
        <>
          {challenge.kind === 'mfa_setup' ? <TotpSetup challenge={challenge} /> : null}
          <DynamicAuthForm
            config={config}
            fields={challengeFields(challenge, config.copy)}
            key={challenge.continuationToken}
            onSubmit={(values) =>
              continueChallenge(stringFormValues(values, ['confirmPassword']))
            }
            submitLabel={
              challenge.kind === 'password' ||
              challenge.kind === 'new_password' ||
              challenge.kind === 'password_reset'
                ? config.copy.continueLabel
                : config.copy.codeSubmit
            }
            submitting={state.submitting}
          />
          {challenge.kind === 'email_verification' ? (
            <button
              className={className(config, 'linkButton')}
              disabled={state.submitting}
              onClick={() => void resendVerification()}
              type="button"
            >
              {config.copy.resendLabel}
            </button>
          ) : null}
        </>
      )}
    </section>
  )
}
