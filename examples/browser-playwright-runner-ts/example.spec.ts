/**
 * An ordinary Playwright spec. Nothing here knows about Solari — the only
 * change from a suite you already have is the import on the next line, which
 * would normally read `from "@playwright/test"`.
 */
import { test, expect } from "./solari"

test("reads a page in a cloud browser", async ({ page }) => {
  await page.goto("https://example.com")
  await expect(page).toHaveTitle(/Example Domain/)
  await expect(page.locator("h1")).toHaveText("Example Domain")
  // Leave a marker behind. If contexts leaked between tests, the next test
  // would still see it.
  await page.evaluate(() => localStorage.setItem("solari-marker", "first test was here"))
})

test("starts from a fresh context, like local Playwright", async ({ page }) => {
  // Isolation is per test: the previous test's context was closed and its
  // storage discarded, so its marker is gone. What a test DOES inherit is a
  // snapshot of the session's starting storage state (cookies from a login
  // done before the suite), taken once — not the live state of other tests.
  await page.goto("https://example.com")
  const marker = await page.evaluate(() => localStorage.getItem("solari-marker"))
  expect(marker).toBeNull()
})
