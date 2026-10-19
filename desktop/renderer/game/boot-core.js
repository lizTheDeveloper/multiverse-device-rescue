import { applyOptOut } from './opt-out.js';

export async function boot({ storage, importModule, win }) {
  applyOptOut(storage);
  const [{ createController }, { scoutSprite }] = await Promise.all([
    importModule('./controller.js'),
    importModule('../rc/components/scout.js'),
  ]);
  const controller = createController({ win, storage, scoutSprite });
  win.RescueGame = controller;
  win.dispatchEvent(new Event('rescue-game-ready'));
  return controller;
}
