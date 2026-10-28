/* Class page: pick the right download for this computer, keep the checklist
   ticks in this browser, copy the page link on a phone. Works without it. */
(function () {
  "use strict";

  var STORE_KEY = "reclaim-city.class-checklist.v1";

  // ---- Which computer is this? ----
  function detect() {
    var ua = navigator.userAgent || "";
    var plat = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
    // iPadOS reports itself as a Mac; touch points give it away.
    if (/iPhone|iPad|iPod|Android/i.test(ua) || (/Mac/.test(plat) && navigator.maxTouchPoints > 1)) {
      return "phone";
    }
    if (/Win/i.test(plat) || /Windows/i.test(ua)) return "windows";
    if (/Mac/i.test(plat) || /Macintosh/i.test(ua)) return macChip();
    if (/Linux|CrOS/i.test(plat) || /Linux|CrOS/i.test(ua)) return "linux";
    return null;
  }

  // Browsers say "Intel" on every Mac, so ask the graphics chip instead.
  // Unknown means Apple chip: almost every Mac sold since 2021 has one.
  function macChip() {
    try {
      var c = document.createElement("canvas");
      var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (gl) {
        var ext = gl.getExtension("WEBGL_debug_renderer_info");
        var r = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
        if (/Intel|AMD|Radeon|NVIDIA|GeForce/i.test(String(r))) return "mac-x64";
      }
    } catch (e) { /* fall through */ }
    return "mac-arm64";
  }

  var LABELS = {
    "mac-arm64": "This looks like a Mac with an Apple chip.",
    "mac-x64": "This looks like a Mac with an Intel processor.",
    "windows": "This looks like a Windows PC.",
    "linux": "This looks like a Linux computer. There’s no app for Linux yet; use the command line."
  };

  var os = detect();
  var buttons = document.getElementById("dl-buttons");
  var note = document.getElementById("dl-detected");

  if (os && LABELS[os] && note && buttons) {
    note.textContent = LABELS[os] + (os === "linux" ? "" : " The right download is first. Not sure? Check below.");
    note.hidden = false;
    var match = buttons.querySelector('[data-os="' + os + '"]');
    if (match) {
      buttons.insertBefore(match, buttons.firstChild);
      Array.prototype.forEach.call(buttons.children, function (b) {
        if (b !== match) { b.classList.remove("btn-primary"); b.classList.add("btn-secondary"); }
      });
    }
  }

  // Open the first-open steps for this computer only.
  var mac = document.getElementById("steps-mac");
  var win = document.getElementById("steps-win");
  if (mac && win) {
    if (os === "windows") { mac.open = false; win.parentNode.insertBefore(win, mac); }
    else if (os === "mac-arm64" || os === "mac-x64") { win.open = false; }
  }

  if (os === "phone") {
    var phone = document.getElementById("dl-phone");
    if (phone) phone.hidden = false;
  }

  // ---- Copy the page link (phones) ----
  var copyBtn = document.getElementById("copy-url");
  var copyStatus = document.getElementById("copy-status");
  var urlEl = document.getElementById("page-url");
  if (copyBtn && urlEl) {
    copyBtn.addEventListener("click", function () {
      var url = "https://" + urlEl.textContent.trim();
      var done = function () { if (copyStatus) copyStatus.textContent = "Copied."; };
      var fail = function () { if (copyStatus) copyStatus.textContent = "Couldn’t copy. Type the address above instead."; };
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(url).then(done, fail);
        } else { fail(); }
      } catch (e) { fail(); }
    });
  }

  // ---- Checklist ticks, in this browser only ----
  function load() {
    try {
      var raw = window.localStorage.getItem(STORE_KEY);
      var v = raw ? JSON.parse(raw) : {};
      return v && typeof v === "object" ? v : {};
    } catch (e) { return {}; }
  }
  function save(state) {
    try { window.localStorage.setItem(STORE_KEY, JSON.stringify(state)); } catch (e) { /* ticks just won't stick */ }
  }

  var boxes = document.querySelectorAll('.checklist input[type="checkbox"][data-key]');
  var state = load();
  Array.prototype.forEach.call(boxes, function (box) {
    box.checked = state[box.getAttribute("data-key")] === true;
    box.addEventListener("change", function () {
      state[box.getAttribute("data-key")] = box.checked;
      save(state);
    });
  });

  var clear = document.getElementById("checklist-clear");
  if (clear) {
    clear.addEventListener("click", function () {
      state = {};
      save(state);
      Array.prototype.forEach.call(boxes, function (box) { box.checked = false; });
    });
  }
})();
