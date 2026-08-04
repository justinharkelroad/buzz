import assert from "node:assert/strict";
import test from "node:test";
import { JSDOM } from "jsdom";

import { shouldAutofocusComposer } from "./useComposerAutofocus.ts";

test("composer autofocus is allowed while the document body owns focus", () => {
  const { document } = new JSDOM().window;

  assert.equal(shouldAutofocusComposer(document.body, document.body), true);
  assert.equal(shouldAutofocusComposer(null, document.body), true);
});

test("composer autofocus still follows an ordinary navigation button", () => {
  const { document } = new JSDOM("<button>general</button>").window;

  assert.equal(
    shouldAutofocusComposer(document.querySelector("button"), document.body),
    true,
  );
});

test("composer autofocus preserves text entry and overlay interactions", () => {
  const { document } = new JSDOM(`
    <input>
    <button aria-haspopup="dialog">voice settings</button>
    <div data-radix-popper-content-wrapper>
      <div role="dialog" tabindex="-1"><button>voice</button></div>
    </div>
  `).window;

  for (const active of document.querySelectorAll(
    "input, [aria-haspopup], [role='dialog'], [role='dialog'] button",
  )) {
    assert.equal(shouldAutofocusComposer(active, document.body), false);
  }
});
