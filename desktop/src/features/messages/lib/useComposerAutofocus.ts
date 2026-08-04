import * as React from "react";

/**
 * Focus the composer editor on mount and whenever the active draft key
 * changes (channel switch, thread open).
 *
 * Matches the behaviour of Slack/Discord/Signal: the composer is ready to
 * accept typing without an explicit click. The `focus` callback is expected
 * to no-op until the underlying editor is mounted, and to change identity
 * once that happens — so listing it as a dep recovers from the
 * editor-not-ready-yet case on first render.
 *
 * The effect trigger deliberately excludes `disabled`: callers pass a
 * disabled flag that includes transient state like `isSending`, which would
 * otherwise re-fire autofocus after every send. When the main channel and
 * an open thread panel both have composers mounted, that race let the main
 * composer steal focus from the thread composer post-send. We only autofocus
 * on mount and on real navigation events (draft-key change).
 *
 * Guards:
 *  - Skip if the composer is currently disabled (archived channel, no
 *    channel, or in-flight send at the moment of mount).
 *  - Skip if focus already lives in another text-entry surface or an active
 *    overlay interaction. Ordinary navigation buttons remain eligible so a
 *    channel click can still hand focus to its newly mounted composer.
 */
export function shouldAutofocusComposer(
  activeElement: Element | null,
  body: HTMLElement | null,
): boolean {
  if (activeElement === null || activeElement === body) return true;

  const active = activeElement as HTMLElement;
  if (
    active.tagName === "INPUT" ||
    active.tagName === "TEXTAREA" ||
    active.tagName === "SELECT" ||
    active.isContentEditable
  ) {
    return false;
  }

  if (active.getAttribute("aria-haspopup") !== null) return false;

  return !active.closest(
    '[data-radix-popper-content-wrapper], [role="dialog"], [role="menu"]',
  );
}

export function useComposerAutofocus(
  focus: () => void,
  draftKey: string | null | undefined,
  disabled: boolean,
) {
  // We read `disabled` at execution time but intentionally don't depend on
  // it — see the comment above.
  const disabledRef = React.useRef(disabled);
  disabledRef.current = disabled;

  // biome-ignore lint/correctness/useExhaustiveDependencies: draftKey is the trigger; disabled is read via ref
  React.useEffect(() => {
    if (disabledRef.current) return;
    if (typeof document === "undefined") return;
    if (!shouldAutofocusComposer(document.activeElement, document.body)) return;
    focus();
  }, [draftKey, focus]);
}
