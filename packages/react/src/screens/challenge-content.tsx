import { QRCodeSVG } from 'qrcode.react'

import { challengeParameter } from '../challenge.js'
import { className } from '../config.js'
import { useAuth } from '../context.js'
import type {
  AuthClientChallenge,
  ResolvedAuthUiConfig
} from '../types.js'
import { RecoveryCodeList } from './recovery-code-list.js'

export function ChallengeSelection({
  challenge
}: {
  readonly challenge: AuthClientChallenge
}) {
  const { config, state, continueChallenge } = useAuth()
  const available = challenge.parameters?.['availableChallenges']
  const choices = Array.isArray(available) ? available : []

  if (choices.length === 0) {
    return <UnsupportedChallenge challenge={challenge} />
  }

  return (
    <div className={className(config, 'actions')}>
      {choices.map((choice) => (
        <button
          className={className(config, 'button')}
          disabled={state.submitting}
          key={choice}
          onClick={() => void continueChallenge({ challenge: choice })}
          type="button"
        >
          {choice.replaceAll('_', ' ').toLowerCase()}
        </button>
      ))}
    </div>
  )
}

export function TotpSetup({
  challenge
}: {
  readonly challenge: AuthClientChallenge
}) {
  const { config } = useAuth()
  return <TotpSetupContent challenge={challenge} config={config} />
}

export function TotpSetupContent({
  challenge,
  config
}: {
  readonly challenge: AuthClientChallenge
  readonly config: ResolvedAuthUiConfig
}) {
  const secret = challengeParameter(challenge, 'secret')
  const uri = challengeParameter(challenge, 'uri')
  const recoveryCodes = challenge.parameters?.['recoveryCodes']

  return (
    <div data-auth-totp-setup="">
      {uri ? (
        <QRCodeSVG
          aria-label="Scan this code with your authenticator app"
          className={className(config, 'totpQrCode')}
          role="img"
          size={192}
          value={uri}
        />
      ) : null}
      {secret ? (
        <p className={className(config, 'description')}>
          <span>Manual setup code: </span>
          <code>{secret}</code>
        </p>
      ) : null}
      {Array.isArray(recoveryCodes) && recoveryCodes.length > 0 ? (
        <RecoveryCodeList codes={recoveryCodes} />
      ) : null}
    </div>
  )
}

export function UnsupportedChallenge({
  challenge
}: {
  readonly challenge: AuthClientChallenge
}) {
  const { config } = useAuth()

  return (
    <p
      className={className(config, 'error')}
      data-auth-unsupported-challenge={challenge.kind}
      role="alert"
    >
      {config.copy.unsupportedChallenge}
    </p>
  )
}
