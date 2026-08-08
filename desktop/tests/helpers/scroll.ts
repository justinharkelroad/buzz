import type { Locator } from "@playwright/test";

const STABLE_FRAMES = 3;
const STABLE_TIMEOUT_MS = 5_000;

/**
 * Resolves once a scroll container's `scrollTop` has held steady across
 * several consecutive animation frames.
 *
 * Conversation surfaces pin themselves to the bottom over more than one frame
 * after mount: an initial pin, a settling re-pin that runs inside the
 * container's own `scroll` handler, and a composer-height measurement pass.
 * A test that writes `scrollTop` inside that window has its write undone
 * before the next round trip, so whatever it samples afterwards is the bottom
 * row rather than the position it asked for. Await this before taking control
 * of a timeline's scroll position, and again afterwards, so every sample comes
 * from a settled layout instead of a racing one.
 */
export async function waitForStableScroll(
  container: Locator,
  { frames = STABLE_FRAMES, timeoutMs = STABLE_TIMEOUT_MS } = {},
): Promise<void> {
  await container.evaluate(
    async (element, options) => {
      const nextFrame = () =>
        new Promise<void>((resolve) => {
          requestAnimationFrame(() => resolve());
        });

      const deadline = performance.now() + options.timeoutMs;
      let previous = element.scrollTop;
      let held = 0;

      while (held < options.frames) {
        if (performance.now() > deadline) {
          throw new Error(
            `Scroll container never settled (scrollTop ${element.scrollTop} still moving after ${options.timeoutMs}ms)`,
          );
        }
        await nextFrame();
        if (element.scrollTop === previous) {
          held += 1;
          continue;
        }
        previous = element.scrollTop;
        held = 0;
      }
    },
    { frames, timeoutMs },
  );
}
