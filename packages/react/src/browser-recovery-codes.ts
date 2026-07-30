const RECOVERY_CODES_FILENAME = 'recovery-codes.txt'

export async function copyRecoveryCodes(
  codes: readonly string[]
): Promise<void> {
  await navigator.clipboard.writeText(codes.join('\n'))
}

export function downloadRecoveryCodes(codes: readonly string[]): void {
  const url = URL.createObjectURL(
    new Blob([codes.join('\n')], { type: 'text/plain;charset=utf-8' })
  )
  const link = document.createElement('a')
  link.href = url
  link.download = RECOVERY_CODES_FILENAME
  link.click()
  URL.revokeObjectURL(url)
}
