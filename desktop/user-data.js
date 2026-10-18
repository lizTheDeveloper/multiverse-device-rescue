// Where the app keeps what it saves (localStorage: the game's progress, the
// display preference). Electron names this folder after the app, so renaming
// the app would start everyone over with nothing. It stays in the folder
// every earlier version used. The name is never shown.
const path = require('path');

const DATA_DIR_NAME = 'Device Rescue';

function userDataDir(appDataDir) {
  return path.join(String(appDataDir), DATA_DIR_NAME);
}

module.exports = { DATA_DIR_NAME, userDataDir };
