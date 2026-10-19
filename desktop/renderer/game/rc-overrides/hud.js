// Stands in for Reclaim City's components/hud.js inside the desktop app. Every game
// screen draws the game's HUD at the top, and that HUD carries the game's
// payment links. The desktop app draws its own HUD (the two counts) above the
// screen instead, so this one draws nothing. app-protocol.js serves this file at
// rc/components/hud.js; rc-files.json says so.
export function renderHud() {
  return '';
}
