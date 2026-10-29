// The 'open-virustotal' channel opens VirusTotal's page for one file's
// fingerprint. Only the sha256 crosses IPC; the URL is built here, so the
// channel can only ever open https://www.virustotal.com/gui/file/<64 hex>.
// It's a lookup of the fingerprint: nothing is uploaded.
const SHA256 = /^[0-9a-f]{64}$/;

function virusTotalUrlFor(sha256) {
  return typeof sha256 === 'string' && SHA256.test(sha256)
    ? `https://www.virustotal.com/gui/file/${sha256}`
    : null;
}

module.exports = { virusTotalUrlFor };
