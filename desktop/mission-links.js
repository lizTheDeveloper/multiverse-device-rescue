// Allowlist for the 'open-mission-link' IPC channel: exact URLs from the
// vendored game's own mission data (mission-links.json, generated). Matching is
// exact string equality, so look-alike hosts, extra paths and added queries
// never match, and nothing is rewritten first.
const { links } = require('./mission-links.json');

const ALLOWED = new Set(links.filter((l) => typeof l === 'string' && l.startsWith('https://')));

function isAllowedMissionLink(url) {
  return typeof url === 'string' && ALLOWED.has(url);
}

module.exports = { isAllowedMissionLink };
