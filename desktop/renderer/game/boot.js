import { boot } from './boot-core.js';

boot({ storage: window.localStorage, importModule: (s) => import(s), win: window })
  .catch((err) => { console.error('Game mode could not start:', err); });
