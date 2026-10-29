// A second opinion on one file, as a per-item action on a lead's case: a
// virus scan's finding carries the file's fingerprint (data.sha256), and
// LOOK IT UP ON VIRUSTOTAL opens VirusTotal's page for that fingerprint in the
// browser. Only the fingerprint goes to main (the 'open-virustotal' channel
// builds the URL); nothing is uploaded. What VirusTotal is and how to read it
// is taught once, in the known-malware lesson; here, only the warning that
// must sit next to the upload. Pure; no DOM.
import { esc } from './escape.js';

const SHA256 = /^[0-9a-f]{64}$/;

export function fingerprintOf(finding) {
  const data = finding && finding.data && typeof finding.data === 'object' ? finding.data : {};
  return typeof data.sha256 === 'string' && SHA256.test(data.sha256) ? data.sha256 : null;
}

export const UPLOAD_WARNING = 'If VirusTotal says it has never seen this file, you can upload it yourself on its site, but only programs and scripts. Never upload anything private (documents, photos, anything with your name, passwords or work files): uploads can be seen and downloaded by VirusTotal’s paying customers.';

// '' for a finding without a fingerprint.
export function lookupHtml(finding) {
  const sha = fingerprintOf(finding);
  if (!sha) return '';
  return `<details class="panel vt-lookup"><summary class="label">LOOK IT UP ON VIRUSTOTAL</summary>
    <p class="intel">Opens VirusTotal’s page for this file’s fingerprint in your browser. Only the fingerprint is looked up; the file isn’t sent.</p>
    <p class="intel faint">Fingerprint (sha256): <code class="vt-sha">${esc(sha)}</code></p>
    <div class="row"><button type="button" class="btn-s" data-act="vt-open:${esc(sha)}">OPEN VIRUSTOTAL ▶</button>
    <button type="button" class="btn-t" data-go="lesson:known-malware">HOW TO READ IT ▶</button></div>
    <p class="intel"><strong>${esc(UPLOAD_WARNING)}</strong></p>
  </details>`;
}

// The sha256 of a 'vt-open:<sha>' act, or null.
export function lookupActSha(act) {
  if (typeof act !== 'string' || !act.startsWith('vt-open:')) return null;
  const sha = act.slice(8);
  return SHA256.test(sha) ? sha : null;
}
