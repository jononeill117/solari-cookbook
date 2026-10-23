/**
 * Runs your Playwright specs on a Solari cloud browser — no local Chromium.
 *
 * In each spec, change
 *   import { test, expect } from '@playwright/test'
 * to
 *   import { test, expect } from './solari'
 * and change nothing else.
 *
 * Then just run `npx playwright test`. solari.global.ts mints a session
 * before the suite and releases it after, so the only thing you need in the
 * environment is SOLARI_API_KEY. Install the runner with
 * PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 — no browser binary is ever used.
 *
 * Why a fixture and not `use.connectOptions` in the config: connectOptions
 * speaks the Playwright wire protocol, and the browser server rejects any
 * client whose version does not match the one it runs (HTTP 428, matched on
 * Playwright's own User-Agent). That pin is currently patchright 1.62.2 and it
 * moves. CDP has no version gate, so connecting this way is the price of never
 * being pinned to whatever we happen to run today.
 *
 * Isolation matches local Playwright: every test gets a FRESH context and
 * page, and whatever it does — cookies, storage, extra tabs — is discarded
 * when the context closes at the end of the test. Auth survives because the
 * fresh context is seeded from a snapshot of the session's starting storage
 * state (see solariStorageState below): a login done before the suite starts
 * is inherited by each test as its starting point, but one test's changes
 * never leak into the next.
 *
 * Trade-off: overriding `context` means Playwright's own trace/video/
 * screenshot-on-failure are off. Solari's session replay is the artifact instead.
 */
import { test as base, chromium, type Browser, type StorageState } from '@playwright/test'

export { expect } from '@playwright/test'

export const test = base.extend<{}, { solariBrowser: Browser; solariStorageState: StorageState }>({
  // Worker-scoped, so one CDP connection is opened and closed once for the whole
  // file. Per-test would be tidier to read and wrong: closing a CDP-connected
  // browser ends the remote Chrome, which would kill the session mid-suite.
  solariBrowser: [
    async ({}, use) => {
      const endpoint = process.env.SOLARI_CDP_ENDPOINT
      if (!endpoint) throw new Error('SOLARI_CDP_ENDPOINT is not set — mint a session first')
      const browser = await chromium.connectOverCDP(endpoint, { timeout: 30_000 })
      await use(browser)
      await browser.close()
    },
    { scope: 'worker' },
  ],

  // Worker-scoped snapshot of the session's starting auth state, taken once
  // from the context the session was minted with. It is a snapshot, not the
  // live context: later writes by any test go to that test's own context and
  // are never folded back in here.
  solariStorageState: [
    async ({ solariBrowser }, use) => {
      const sessionContext = solariBrowser.contexts()[0]
      await use(sessionContext ? await sessionContext.storageState() : { cookies: [], origins: [] })
    },
    { scope: 'worker' },
  ],

  // Test-scoped (Playwright's default), unlike the two fixtures above. A new
  // context per test on the shared browser is cheap and safe: closing a
  // context ends only that context — the browser and the session stay up for
  // the next test. Seeding it with the snapshot above is what carries the
  // session's cookies into the test; skipping the seed would start every
  // test signed out on about:blank.
  context: async ({ solariBrowser, solariStorageState }, use) => {
    const context = await solariBrowser.newContext({ storageState: solariStorageState })
    await use(context)
    await context.close()
  },
  page: async ({ context }, use) => {
    await use(await context.newPage())
  },
})
