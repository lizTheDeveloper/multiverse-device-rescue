// The profile screen as production sees it: the publish control and the
// consent sheet exist only while PUBLISH_READY is true (it is false today).
import { PUBLISH_READY } from '../profile/publish.js';
import { createProfileRenderer, createPublishSheet } from './profile-core.js';

export { START_OVER, CLEAR_PROGRESS, focusProfile, profileKeyAct } from './profile-core.js';
export const renderProfile = createProfileRenderer(PUBLISH_READY);
export const renderPublishSheet = createPublishSheet(PUBLISH_READY);
