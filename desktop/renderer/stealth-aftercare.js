'use strict';

/*
 * The short note shown once, right after the display preference switches to
 * 'city' (the first question's "Yes", the "watching me" worry, the follow-up's
 * "No, I don't", or "Something changed?"). It says what the city does for
 * the person, then gets out of the way. It is help content, like the
 * generated district, so it may say what the rest of the city never says.
 * Nothing about it is ever written to storage: it shows on the switch itself,
 * which only happens once per change of mode.
 *
 * Reachable again from the generated district ("What this mode does").
 *
 * Loaded as a plain script (global `StealthAftercare`); tested from Node.
 */
const StealthAftercare = (function () {
  // The district's own tile label (game/views/side-district.js TILE_LABEL).
  const TILE_LABEL = 'ALSO IN TOWN';
  // Word for word from the Six Roses guide (desktop/test/fixtures/six-roses-excerpt.txt).
  const HOTLINE = 'National Domestic Violence Hotline: 1-800-799-7233. Text “START” to 88788.';

  // Shown on a switch into 'city' only: never on launch, never when it already was.
  function due(before, after) {
    return before !== 'city' && after === 'city';
  }

  // `place`: the install's generated district name ('' when the game isn't ready).
  function points(place) {
    const there = place || 'that place';
    return [
      'To anyone glancing at the screen, this app looks like a city-building game.',
      place
        ? `Help and quiet next steps are in a place in the city called ${place}. Its tile is on the city, under ${TILE_LABEL}.`
        : `Help and quiet next steps are in a place in the city. Its tile is on the city, under ${TILE_LABEL}.`,
      `In ${there}, press Esc to jump straight back to the game.`,
      'If the checkup finds software that could be watching you, this app won’t remove it or tell you to. It will suggest talking to an advocate first, because removing it can alert whoever installed it.',
      `Nothing saved on this computer says what this is about. You can change this anytime with “Something changed?” in ${there}.`,
    ];
  }

  function copy({ place = '', again = false, canVisit = true } = {}) {
    const there = place || 'that place';
    return {
      title: again ? 'What this mode does' : 'Thank you for telling us',
      lede: again ? '' : 'You’re not alone, and you don’t have to decide anything. Here’s how this app works for you:',
      points: points(place),
      help: `${HOTLINE} More help is in ${there}.`,
      go: again ? `Back to ${there}` : 'Go to the city',
      visit: again || !canVisit ? '' : `Show me ${there} first`,
      esc: 'Press Esc to go straight to the game.',
    };
  }

  function html(opts, esc) {
    const c = copy(opts);
    // tabindex="-1": app.js moves focus here so a screen reader reads it first.
    return `<h1 id="aftercare-title" tabindex="-1">${esc(c.title)}</h1>${c.lede ? `
      <p class="lede">${esc(c.lede)}</p>` : ''}
      <ul class="aftercare-points">${c.points.map((p) => `
        <li>${esc(p)}</li>`).join('')}
      </ul>
      <p class="aftercare-help muted">${esc(c.help)}</p>
      <div class="aftercare-actions">
        <button type="button" class="btn btn--primary" data-aftercare="go">${esc(c.go)}</button>${c.visit ? `
        <button type="button" class="btn btn--secondary" data-aftercare="visit">${esc(c.visit)}</button>` : ''}
      </div>
      <p class="muted">${esc(c.esc)}</p>`;
  }

  return { TILE_LABEL, HOTLINE, due, copy, html };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = StealthAftercare;
}
