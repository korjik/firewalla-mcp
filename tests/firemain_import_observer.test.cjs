'use strict';
const assert = require('node:assert/strict');
const {projectExistingInstances} = require('../scripts/firemain_import_observer.cjs');

let attributesCalled = false;
const safeInstance = started => ({
  isStarted: () => started,
  get settings() { throw new Error('must not inspect settings'); },
  getAttributes() { attributesCalled = true; throw new Error('secret-value'); },
  start() { throw new Error('must not start'); },
  stop() { throw new Error('must not stop'); }
});
const registry = {one: safeInstance(false), two: safeInstance(true), three: null};
const result = projectExistingInstances(id => registry[id], ['one', 'two', 'three']);
assert.deepEqual(result.observations.map(row => row.administrative_observation), ['stopped', 'started', 'not_instantiated']);
assert.equal(result.safe_to_import, false);
assert.equal(attributesCalled, false);
assert.equal(projectExistingInstances(() => undefined, ['one']).observations[0].administrative_observation, 'unknown');
assert.equal(projectExistingInstances(() => safeInstance(undefined), ['one']).observations[0].administrative_observation, 'unknown');
assert.equal(projectExistingInstances(() => safeInstance('false'), ['one']).observations[0].administrative_observation, 'unknown');
assert.equal(projectExistingInstances(() => safeInstance(0), ['one']).observations[0].administrative_observation, 'unknown');
const failure = projectExistingInstances(() => { throw new Error('secret-value'); }, ['one']);
assert.equal(failure.observations[0].administrative_observation, 'unknown');
assert.ok(!JSON.stringify(failure).includes('secret-value'));
for (const ids of [[], ['../one'], ['one;id'], ['one', 'one'], ['one','two','three','four']]) {
  assert.throws(() => projectExistingInstances(() => null, ids));
}
assert.throws(() => projectExistingInstances(null, ['one']));
console.log('PASS: FireMain observation projection; no attributes/lifecycle calls; incomplete evidence never authorizes import');
