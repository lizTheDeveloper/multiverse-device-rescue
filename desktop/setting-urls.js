// Allowlist for the 'open-setting' IPC channel.
//
// shell.openExternal hands a URL straight to the OS handler, so an unrestricted
// channel would let anything that can reach the renderer — a future markup
// injection bug, or a tampered permissions-content.json arriving through the
// content-update path — launch local files and registered protocol handlers.
// These are the only schemes the permissions walkthrough actually needs.
const ALLOWED_SETTING_SCHEMES = ['x-apple.systempreferences:', 'ms-settings:'];

function isAllowedSettingUrl(url) {
  if (typeof url !== 'string') return false;
  // Match on the exact scheme prefix. Nothing is stripped or rewritten first:
  // sanitising a URL invites parser-differential bugs, allowlisting does not.
  return ALLOWED_SETTING_SCHEMES.some((scheme) => url.startsWith(scheme));
}

// The 'open-guide' channel opens a page in the browser. Only the project's
// own documentation site and Reclaim City, the same team's privacy game (the
// results page's "learn this properly" link), are allowed. Each prefix ends in
// a path segment and '/', so look-alike hosts and sibling paths don't match.
const GUIDE_URL_PREFIX = 'https://lizthedeveloper.github.io/multiverse-device-rescue/';
const GAME_URL_PREFIX = 'https://play.multiversegames.ai/reclaim-city/';
const ALLOWED_GUIDE_PREFIXES = [GUIDE_URL_PREFIX, GAME_URL_PREFIX];

function isAllowedGuideUrl(url) {
  return typeof url === 'string' && ALLOWED_GUIDE_PREFIXES.some((prefix) => url.startsWith(prefix));
}

module.exports = {
  isAllowedSettingUrl,
  ALLOWED_SETTING_SCHEMES,
  isAllowedGuideUrl,
  GUIDE_URL_PREFIX,
  GAME_URL_PREFIX,
};
