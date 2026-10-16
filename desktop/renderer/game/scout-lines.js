// Scout's fixed lines. Short, plain, never a promise that everything is fine.
// They are placeholders listed for review in the spec (section 9).
export const SCOUT = {
  mapHot: 'Start with {district}. Something there is worth a look first. Finding something doesn’t mean you’ve been hacked.',
  mapWarn: 'Nothing urgent. {district} has the most worth a look.',
  mapQuiet: 'Nothing stood out in the checks that ran. Fog means a place I couldn’t see into.',
  cameBack: 'Something you fixed came back since last time. It’s dark again on the map.',
  briefing: {
    critical: 'This one is worth doing first. Read what it is, then pick how you want to handle it.',
    warning: 'This isn’t urgent, but it’s worth a look when you’re ready.',
  },
  checking: 'Checking again. This only looks; it doesn’t change anything.',
  reclaimed: 'Device Rescue checked again, and it’s gone.',
  notYet: 'It’s still showing. Some programs put themselves back. Let’s look at the steps again.',
  couldnt: 'I couldn’t check again just now. That doesn’t mean it’s fixed.',
  yours: 'Marked as yours. It stays listed, and you can change your mind any time.',
  debrief: {
    easy: 'Good. Every one you do makes the next one easier.',
    nervous: 'That’s normal. You did it anyway, and Device Rescue kept a way back.',
    worried: 'That’s fair. The rest of the city is still here, and the list view has every detail.',
  },
};

export function mapScoutLine(city) {
  const ds = (city && city.districts) || [];
  const hot = ds.find((d) => d.status === 'hot');
  if (hot) return SCOUT.mapHot.replace('{district}', hot.name);
  const warm = ds.filter((d) => d.status === 'warn').sort((a, b) => b.missions.length - a.missions.length)[0];
  if (warm) return SCOUT.mapWarn.replace('{district}', warm.name);
  return SCOUT.mapQuiet;
}

export function debriefReply(answer) {
  return SCOUT.debrief[answer] || SCOUT.debrief.easy;
}
