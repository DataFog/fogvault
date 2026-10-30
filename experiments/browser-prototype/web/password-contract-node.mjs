// Execute shared/detached-buffer ownership rules where SharedArrayBuffer is
// available. This is Node evidence for the same helper, not browser qualification.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {passwordTextArguments, validatePasswordBytes, wipePasswordArguments} from './password.mjs';

const cases = [];
const run = (id, check) => { check(); cases.push({id, status: 'pass', executed: true}); };
const rejected = fn => assert.throws(fn, error => error.code === 'InvalidInput');
run('shared_buffer_rejected_without_wipe', () => {
  assert.equal(typeof SharedArrayBuffer, 'function');
  const shared = new Uint8Array(new SharedArrayBuffer(3)); shared.set([1, 2, 3]);
  rejected(() => validatePasswordBytes('unlock', {password: shared}));
  wipePasswordArguments('unlock', {password: shared});
  assert.deepEqual([...shared], [1, 2, 3]);
});
run('detached_buffer_rejected_as_distinct_from_empty', () => {
  const detached = new Uint8Array([65, 0, 66]);
  const moved = structuredClone(detached.buffer, {transfer: [detached.buffer]});
  rejected(() => validatePasswordBytes('unlock', {password: detached}));
  wipePasswordArguments('unlock', {password: detached});
  assert.deepEqual([...new Uint8Array(moved)], [65, 0, 66]);
  validatePasswordBytes('unlock', {password: new Uint8Array()});
});
run('owned_text_buffers_cleared', () => {
  const original = {password: ' é\0🦀 ', new_password: 'e\u0301'};
  const args = passwordTextArguments('change_password', original);
  assert.notDeepEqual([...args.password], []);
  validatePasswordBytes('change_password', args);
  wipePasswordArguments('change_password', args);
  assert(args.password.every(byte => byte === 0));
  assert(args.new_password.every(byte => byte === 0));
  assert.equal(original.password, ' é\0🦀 ');
});
const source_identity = Object.fromEntries([
  ['experiments/browser-prototype/web/password.mjs', new URL('./password.mjs', import.meta.url)],
  ['experiments/browser-prototype/web/password-contract-node.mjs', import.meta.url],
].map(([path, url]) => [path, createHash('sha256').update(readFileSync(new URL(url))).digest('hex')]));
console.log(JSON.stringify({schema: 'fogvault-browser-password-adapter-node/v1', pass: true, executed: true,
  scope: 'node-helper-only-no-browser-SAB-qualification', node: process.version,
  shared_array_buffer_available: true, cases, source_identity}));
