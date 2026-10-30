'use strict';

/* Observation-only helper, NOT installed or an endpoint. No Firewalla modules
 * are imported here. A reviewed in-process host would pass the already-loaded
 * VPNClient.getInstance function, never construct a new VPNClient.
 * No profile attributes, credentials, settings, Redis, network, or lifecycle calls.
 */
function projectExistingInstances(getInstance, targetIds) {
  if (typeof getInstance !== 'function' || !Array.isArray(targetIds) ||
      targetIds.length < 1 || targetIds.length > 3 ||
      new Set(targetIds).size !== targetIds.length ||
      !targetIds.every(id => typeof id === 'string' && /^[A-Za-z0-9_]{1,10}$/.test(id))) {
    throw new Error('Invalid fixed-target observation request');
  }
  const rows = targetIds.map(id => {
    let presence = 'unknown';
    let intent = 'unknown';
    try {
      const instance = getInstance(id);
      if (instance === null) {
        presence = 'absent';
        intent = 'not_instantiated';
      } else if (instance !== undefined && typeof instance.isStarted === 'function') {
        presence = 'present';
        const started = instance.isStarted();
        if (started === true) intent = 'started';
        else if (started === false) intent = 'stopped';
      }
    } catch (_) {
      // Do not return exception messages: implementations can include secrets.
      intent = 'unknown';
    }
    return {profile_id: id, instance: presence, administrative_observation: intent};
  });
  return {
    observations: rows,
    observation_only: true,
    safe_to_import: false,
    outstanding: ['authenticated in-process attachment', 'complete reference checks',
      'concurrent lifecycle/event exclusion', 'installed-source compatibility']
  };
}

module.exports = {projectExistingInstances};
