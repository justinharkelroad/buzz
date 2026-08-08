import type { Locator } from "@playwright/test";

const HOLD_MS = 200;
const TIMEOUT_MS = 5_000;

/**
 * Focuses an element and resolves only once it has *kept* focus for a hold
 * window, re-focusing and re-checking if something steals it first.
 *
 * Dialogs hand out focus more than once on open: the overlay library focuses
 * its first focusable child synchronously, and a component may then move focus
 * again from a timer. `toBeFocused()` is satisfied by the first of those and
 * says nothing about the second still being queued. A test that starts typing
 * in that gap can have the pending `focus()` land between Playwright's
 * focus step and its text insertion, so the text is inserted into whichever
 * field the timer chose — the two fields silently concatenate.
 *
 * Awaiting a settled focus before typing drains the queued handoff, the same
 * way `waitForStableScroll` drains a container's queued scroll pinning.
 */
export async function focusAndHold(
  target: Locator,
  { holdMs = HOLD_MS, timeoutMs = TIMEOUT_MS } = {},
): Promise<void> {
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    await target.focus();
    const held = await target.evaluate(async (element, ms) => {
      const start = performance.now();
      while (performance.now() - start < ms) {
        await new Promise((resolve) => {
          requestAnimationFrame(() => resolve(null));
        });
        if (document.activeElement !== element) return false;
      }
      return true;
    }, holdMs);

    if (held) return;
    if (Date.now() > deadline) {
      throw new Error(
        `Focus never settled on the target: it was stolen repeatedly within ${holdMs}ms for ${timeoutMs}ms`,
      );
    }
  }
}
