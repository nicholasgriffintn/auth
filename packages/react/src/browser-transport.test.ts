import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  createBrowserAuthTransport,
  followBrowserAuthRedirect
} from './browser-transport.js'

describe('browser authentication transport', () => {
  it('posts shared requests to the central authentication endpoint', async () => {
    let receivedInput: RequestInfo | URL | undefined
    let receivedInit: RequestInit | undefined
    const transport = createBrowserAuthTransport({
      request: async (input, init) => {
        receivedInput = input
        receivedInit = init
        return Response.json({
          status: 'redirect_required',
          provider: 'mastodon',
          url: 'https://mastodon.social/oauth/authorize'
        })
      }
    })

    const result = await transport.execute({
      action: 'start_oauth',
      provider: 'mastodon',
      values: { server: 'mastodon.social' }
    })

    assert.equal(receivedInput, '/api/auth')
    assert.equal(
      receivedInit?.body,
      JSON.stringify({
        action: 'start_oauth',
        provider: 'mastodon',
        values: { server: 'mastodon.social' }
      })
    )
    assert.equal(result.status, 'redirect_required')
  })

  it('rejects invalid service responses', async () => {
    const transport = createBrowserAuthTransport({
      request: async () => Response.json({ status: 'made_up' })
    })

    await assert.rejects(
      transport.execute({ action: 'sign_out' }),
      /invalid response/
    )
  })

  it('uses a service error message for the user-facing flow', async () => {
    const transport = createBrowserAuthTransport({
      request: async () =>
        new Response(JSON.stringify({ error: 'That account is unavailable.' }), {
          status: 409
        })
    })

    await assert.rejects(
      transport.execute({ action: 'sign_out' }),
      /That account is unavailable/
    )
  })
})

it('rejects non-web authentication redirects', () => {
  const originalLocation = Object.getOwnPropertyDescriptor(
    globalThis,
    'location'
  )
  Object.defineProperty(globalThis, 'location', {
    configurable: true,
    value: {
      href: 'https://app.example/sign-in',
      assign() {
        assert.fail('Unsafe redirect was followed.')
      }
    }
  })
  try {
    assert.throws(
      () => followBrowserAuthRedirect('javascript:alert(1)'),
      /invalid redirect/
    )
  } finally {
    if (originalLocation) {
      Object.defineProperty(globalThis, 'location', originalLocation)
    } else {
      Reflect.deleteProperty(globalThis, 'location')
    }
  }
})
