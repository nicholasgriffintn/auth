import { className } from '../config.js'
import { useAuth } from '../context.js'
import { RecoveryCodeList } from './recovery-code-list.js'

export function RecoveryCodesScreen() {
  const { completeRecoveryCodes, config, recoveryCodes, state } = useAuth()

  return (
    <section aria-labelledby="auth-recovery-codes-title" data-auth-screen="recovery-codes">
      <h2 className={className(config, 'title')} id="auth-recovery-codes-title">
        {config.copy.recoveryCodesTitle}
      </h2>
      <RecoveryCodeList codes={recoveryCodes}>
        <button
          className={className(config, 'button')}
          disabled={state.submitting}
          onClick={() => void completeRecoveryCodes()}
          type="button"
        >
          {config.copy.continueLabel}
        </button>
      </RecoveryCodeList>
    </section>
  )
}
