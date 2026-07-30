import { useId, type RefObject } from 'react'

import { className } from '../config.js'
import { useAuth } from '../context.js'
import { DynamicAuthForm } from '../dynamic-form.js'
import type { ExternalAuthProvider } from '../types.js'

export function ProviderFieldDialog({
  dialog,
  onClose,
  onSubmit,
  provider
}: {
  readonly dialog: RefObject<HTMLDialogElement | null>
  readonly onClose: () => void
  readonly onSubmit: (
    values: Readonly<Record<string, string | boolean>>
  ) => void | Promise<void>
  readonly provider: ExternalAuthProvider
}) {
  const { config, state } = useAuth()
  const titleId = useId()

  return (
    <dialog
      aria-labelledby={titleId}
      className={className(config, 'dialog')}
      onClick={(event) => {
        if (event.target === event.currentTarget) dialog.current?.close()
      }}
      onClose={onClose}
      ref={dialog}
    >
      <div className={className(config, 'dialogContent')}>
        <h2 className={className(config, 'title')} id={titleId}>
          {provider.formTitle ?? provider.label}
        </h2>
        {provider.formDescription ? (
          <p className={className(config, 'description')}>{provider.formDescription}</p>
        ) : null}
        <DynamicAuthForm
          cancelLabel={config.copy.cancelLabel}
          config={config}
          fields={provider.fields ?? []}
          onCancel={() => dialog.current?.close()}
          onSubmit={onSubmit}
          submitLabel={provider.submitLabel ?? config.copy.continueLabel}
          submitting={state.submitting}
        />
      </div>
    </dialog>
  )
}
