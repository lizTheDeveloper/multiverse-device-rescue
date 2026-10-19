'use strict';

/*
 * Text from the scan shown as it is: control and format characters (newlines,
 * carriage returns, bidi overrides, zero-width spaces) and the line and
 * paragraph separators U+2028/2029 become a visible [U+XXXX]. So a value can't
 * start a new line that reads like another row ("Made by: Apple · verified"),
 * reorder itself or hide part of itself, on screen, on the clipboard or in a
 * question to an AI. One rule for the evidence block and the "It's mine" panel.
 *
 *   VisibleText.CONTROL_OR_FORMAT -> RegExp (no g flag): any such character
 *   VisibleText.visible(s) -> s with each one as [U+XXXX]
 *
 * Loaded as a plain script (global `VisibleText`, before mark-flow.js and
 * evidence.js); tested from Node.
 */
const VisibleText = (function () {
  const CONTROL_OR_FORMAT = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
  const ALL = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;
  function visible(s) {
    return String(s == null ? '' : s).replace(ALL, (c) => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`);
  }
  return { CONTROL_OR_FORMAT, visible };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = VisibleText;
}
if (typeof window !== 'undefined') {
  window.VisibleText = VisibleText;
}
