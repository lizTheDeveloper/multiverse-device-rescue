// A remote-access tool's evidence (the engine's remote_access_tools data), in
// the plain sentences both the Guest Book's card and the help district show:
// when it was added, when it last let someone in, whether it can let someone in
// without a click, and whether it's running. Missing evidence (null) reads
// "Couldn't tell", never "no" and never safe. Pure; dates through day.js, so
// "2026-03-03" is March 3 in every timezone.
//
//   remoteFacts(data, { today, year, locale }) -> { added, last_in, unattended, running, running_now: true|false|null, rows }
//   rows: the same facts as label/value rows for an evidence card (the help district's held card).
const COULDNT = 'Couldn’t tell';
import { dayWords } from './day.js';

export function remoteFacts(data, { today, year = false, locale } = {}) {
  const d = data && typeof data === 'object' ? data : {};
  const added = dayWords(d.added_on, { today, year, locale });
  const last = dayWords(d.last_incoming, { today, year, locale });
  const n = Number.isInteger(d.incoming_count) && d.incoming_count >= 0 ? d.incoming_count : null;
  const times = n === 1 ? 'once' : `${n} times`;
  let lastIn = 'Couldn’t tell when it last let someone in';
  if (n === 0) lastIn = 'Its connection list shows no one let in';
  else if (n && last) lastIn = `Last let someone in: ${last} (${times})`;
  else if (n) lastIn = `Let someone in ${times} (couldn’t tell when)`;
  let lastValue = COULDNT;
  if (n === 0) lastValue = 'No one, by its connection list';
  else if (n && last) lastValue = `${last} (${times})`;
  else if (n) lastValue = `${times} (couldn’t tell when)`;
  const yesNo = (v, no) => (v === true ? 'Yes' : v === false ? no : COULDNT);
  const rows = [
    { label: 'Added', value: added || COULDNT },
    { label: 'Last let someone in', value: lastValue },
    { label: 'Can let someone in without a click', value: yesNo(d.lets_in_unattended, 'Found no way') },
    { label: 'Running now', value: yesNo(d.running_now, 'No') },
  ];
  return {
    rows,
    added: added ? `Added on ${added}` : 'Couldn’t tell when this was added',
    last_in: lastIn,
    unattended: d.lets_in_unattended === true ? 'Can let someone in without you clicking yes'
      : d.lets_in_unattended === false ? 'Found no way for it to let someone in without you' : 'Couldn’t tell if it can let someone in without you',
    running: d.running_now === true ? 'Running now' : d.running_now === false ? 'Not running now' : 'Couldn’t tell if it’s running now',
    running_now: d.running_now === true ? true : d.running_now === false ? false : null,
  };
}
