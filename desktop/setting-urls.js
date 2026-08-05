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

module.exports = { isAllowedSettingUrl, ALLOWED_SETTING_SCHEMES };
