import assert from 'node:assert/strict'
import test from 'node:test'

import { className } from '../config.js'

test('uses the application button style for built-in sign-in methods', () => {
  const config = { classNames: { button: 'app-button' } }

  assert.equal(className(config, 'passkeyButton'), 'app-button')
  assert.equal(className(config, 'magicLinkButton'), 'app-button')
})
