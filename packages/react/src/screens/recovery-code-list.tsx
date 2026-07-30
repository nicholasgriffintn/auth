import { useState, type ReactNode } from 'react'

import {
  copyRecoveryCodes,
  downloadRecoveryCodes
} from '../browser-recovery-codes.js'
import { className } from '../config.js'
import { useAuth } from '../context.js'
import type { ResolvedAuthUiConfig } from '../types.js'

export function RecoveryCodeList({
  children,
  codes
}: {
  readonly children?: ReactNode
  readonly codes: readonly string[]
}) {
  const { config } = useAuth()
  const [error, setError] = useState<string>()

  async function copy(): Promise<void> {
    try {
      await copyRecoveryCodes(codes)
      setError(undefined)
    } catch {
      setError('Recovery codes could not be copied.')
    }
  }

  return (
    <>
      <p className={className(config, 'description')}>{config.copy.recoveryCodesLabel}</p>
      {error ? (
        <p className={className(config, 'error')} role="alert">
          {error}
        </p>
      ) : null}
      <ul className={className(config, 'recoveryCodes')} data-auth-recovery-codes="">
        {codes.map((code) => (
          <li key={code}>
            <code>{code}</code>
          </li>
        ))}
      </ul>
      <RecoveryCodeActions
        codes={codes}
        config={config}
        onCopy={() => void copy()}
      >
        {children}
      </RecoveryCodeActions>
    </>
  )
}

export function RecoveryCodeActions({
  children,
  codes,
  config,
  onCopy
}: {
  readonly children?: ReactNode
  readonly codes: readonly string[]
  readonly config: ResolvedAuthUiConfig
  readonly onCopy: () => void
}) {
  return (
    <div className={className(config, 'recoveryCodesActions')}>
      <button className={className(config, 'button')} onClick={onCopy} type="button">
        {config.copy.recoveryCodesCopyLabel}
      </button>
      <button
        className={className(config, 'button')}
        onClick={() => downloadRecoveryCodes(codes)}
        type="button"
      >
        {config.copy.recoveryCodesDownloadLabel}
      </button>
      {children}
    </div>
  )
}
