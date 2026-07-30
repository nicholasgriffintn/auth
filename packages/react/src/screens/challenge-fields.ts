import { challengeParameter } from '../challenge.js'
import type {
  AuthClientChallenge,
  AuthCopy,
  AuthField
} from '../types.js'

type ChallengeFieldCopy = Pick<
  AuthCopy,
  | 'codeLabel'
  | 'passwordLabel'
  | 'newPasswordLabel'
  | 'confirmPasswordLabel'
  | 'totpOrRecoveryCodeLabel'
  | 'totpOrRecoveryDescription'
>

type ChallengeTitleCopy = Pick<
  AuthCopy,
  | 'recoveryTitle'
  | 'codeLabel'
  | 'newPasswordLabel'
  | 'passkeyChallengeTitle'
  | 'passkeySetupLabel'
  | 'totpOrRecoveryCodeLabel'
>

export function challengeFields(
  challenge: AuthClientChallenge,
  copy: ChallengeFieldCopy
): readonly AuthField[] {
  switch (challenge.kind) {
    case 'password':
      return [currentPasswordField(copy.passwordLabel)]
    case 'new_password':
      return newPasswordFields(copy)
    case 'password_reset':
      return [codeField(copy.codeLabel), ...newPasswordFields(copy)]
    case 'custom':
      return [
        {
          name: 'answer',
          label: challengeParameter(challenge, 'prompt') ?? copy.codeLabel,
          required: true
        }
      ]
    case 'software_token_mfa':
      return challengeParameter(challenge, 'method') === 'totp_or_recovery'
        ? [
            {
              ...codeField(copy.totpOrRecoveryCodeLabel, false),
              description: copy.totpOrRecoveryDescription
            }
          ]
        : [codeField(copy.codeLabel)]
    default:
      return [codeField(copy.codeLabel)]
  }
}

export function challengeTitle(
  challenge: AuthClientChallenge,
  copy: ChallengeTitleCopy
): string {
  switch (challenge.kind) {
    case 'password_reset':
      return copy.recoveryTitle
    case 'new_password':
      return copy.newPasswordLabel
    case 'webauthn':
      return challengeParameter(challenge, 'ceremony') === 'registration'
        ? copy.passkeySetupLabel
        : copy.passkeyChallengeTitle
    case 'mfa_selection':
      return 'Choose a verification method'
    case 'mfa_setup':
      return 'Set up an authenticator'
    case 'software_token_mfa':
      return challengeParameter(challenge, 'method') === 'totp_or_recovery'
        ? copy.totpOrRecoveryCodeLabel
        : copy.codeLabel
    default:
      return copy.codeLabel
  }
}

function currentPasswordField(label: string): AuthField {
  return {
    name: 'password',
    label,
    type: 'password',
    autoComplete: 'current-password',
    required: true
  }
}

function newPasswordFields(
  copy: Pick<AuthCopy, 'newPasswordLabel' | 'confirmPasswordLabel'>
): readonly AuthField[] {
  return [
    {
      name: 'newPassword',
      label: copy.newPasswordLabel,
      type: 'password',
      autoComplete: 'new-password',
      required: true,
      minLength: 8
    },
    {
      name: 'confirmPassword',
      label: copy.confirmPasswordLabel,
      type: 'password',
      autoComplete: 'new-password',
      required: true,
      validate(value, values) {
        return value === values['newPassword'] ? null : 'Passwords do not match.'
      }
    }
  ]
}

function codeField(label: string, numeric = true): AuthField {
  return {
    name: 'code',
    label,
    autoComplete: 'one-time-code',
    inputMode: numeric ? 'numeric' : 'text',
    required: true,
    minLength: 4,
    maxLength: 2048
  }
}
