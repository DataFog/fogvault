import {test, beforeEach, afterEach} from 'node:test';
import assert from 'node:assert/strict';
import {FogVault, passwordTextToBytes} from '../src/client.mjs';
import {installWorker} from '../src/worker-runtime.mjs';

const options = {limits: {payload: 1024, metadata: 32, records: 16}, storageProfile: 'arraybuffer',
  kdfProfiles: [{memory_kib: 65536, passes: 3}]};
const id = new Uint8Array(16).fill(1), operation = new Uint8Array(16).fill(2);
const receipt = () => ({generation: 0n, request_id: new Uint8Array(16), head_digest: new Uint8Array(32).fill(3)});
let workers, postedWaiters;
class WorkerTransport {
  constructor() { this.messages = []; this.terminated = false; this.autoReady = true; workers.push(this); }
  postMessage(message) {
    const clone = structuredClone(message); this.messages.push(clone);
    for (const waiter of postedWaiters.filter(value => value.action === clone.action)) waiter.resolve({worker: this, message: clone});
    postedWaiters = postedWaiters.filter(value => value.action !== clone.action);
    if (clone.action === 'initialize') queueMicrotask(() => this.onmessage({data: {channel: clone.channel, ready: true}}));
    else if (['create', 'open', 'unlock'].includes(clone.action)) queueMicrotask(() => this.respond(clone, {receipt: receipt(), [clone.action === 'create' ? 'created' : clone.action === 'open' ? 'opened' : 'unlocked']: true}));
  }
  respond(message, result) { this.onmessage?.({data: {channel: message.channel, requestId: message.requestId, ok: true, result}}); }
  terminate() { this.terminated = true; }
}
const posted = action => new Promise(resolve => postedWaiters.push({action, resolve}));
const tick = () => new Promise(resolve => setImmediate(resolve));
beforeEach(() => { workers = []; postedWaiters = []; globalThis.Worker = WorkerTransport; });
afterEach(() => { delete globalThis.Worker; });

test('credentials are snapshotted before async readiness and caller bytes are not wiped', async () => {
  const owner = new FogVault(options), credential = new Uint8Array([97, 98, 99]), transported = posted('create');
  const creation = owner.create('synthetic', credential); credential[0] = 120;
  const {message} = await transported; await creation;
  assert.deepEqual(message.args.password, new Uint8Array([97, 98, 99]));
  assert.deepEqual(credential, new Uint8Array([120, 98, 99]));
  await owner.close();
});

test('lock revokes a posted mutation as unknown with its exact request identity', async () => {
  const owner = new FogVault(options); await owner.create('synthetic', 'SYNTHETIC test password');
  const transported = posted('save_at');
  const saving = owner.save(id, new Uint8Array(), new Uint8Array([5]), {expectedRevision: 0n, requestId: operation});
  const rejected = assert.rejects(saving, error => error.code === 'OutcomeUnknown' && assert.deepEqual(error.requestId, operation) === undefined);
  const {worker, message} = await transported; await owner.lock(); await rejected;
  assert.equal(worker.terminated, true); assert.equal(owner.locked, true);
  worker.respond(message, {receipt: receipt()}); await tick(); assert.equal(owner.locked, true);
  await owner.close();
});

test('lock revokes reads without incorrectly labelling them committed writes', async () => {
  const owner = new FogVault(options); await owner.create('synthetic', 'SYNTHETIC test password');
  const transported = posted('read'), reading = owner.read(id), rejected = assert.rejects(reading, error => error.code === 'Locked');
  await transported; await owner.lock(); await rejected; await owner.close();
});

test('reopening after owner lock creates a fresh Worker before unlock', async () => {
  const owner = new FogVault(options); await owner.create('synthetic', 'SYNTHETIC test password');
  const first = workers[0]; await owner.lock(); await owner.unlock('SYNTHETIC test password');
  assert.equal(first.terminated, true); assert.equal(workers.length, 2);
  assert.deepEqual(workers[1].messages.map(message => message.action), ['initialize', 'open', 'unlock']);
  assert.equal(owner.locked, false); await owner.close();
});

test('mutation intent and payload are captured before transport, including head authority', async () => {
  const owner = new FogVault(options); await owner.create('synthetic', 'SYNTHETIC test password');
  const expectedHead = new Uint8Array(32).fill(7), payload = new Uint8Array([4]), transported = posted('save_at');
  const saving = owner.save(id, new Uint8Array(), payload, {expectedRevision: 0n, expectedHead, requestId: operation});
  payload[0] = 8; expectedHead[0] = 9;
  const {message, worker} = await transported;
  assert.equal(message.args.payload[0], 4); assert.equal(message.args.expected_head[0], 7);
  worker.respond(message, {receipt: receipt(), saved: true}); await saving; await owner.close();
});

test('invalid revisions and malformed credentials fail before Worker transport', async () => {
  const owner = new FogVault(options);
  assert.throws(() => owner.create('synthetic', '\ud800'), error => error.code === 'InvalidInput');
  assert.equal(workers.length, 0); await owner.create('synthetic', 'SYNTHETIC test password');
  const count = workers[0].messages.length;
  for (const value of [0, -1n, 9223372036854775808n, '1']) assert.throws(() => owner.save(id, new Uint8Array(), new Uint8Array(), {expectedRevision: value}), error => error.code === 'InvalidInput');
  assert.equal(workers[0].messages.length, count); await owner.close();
});

test('production Worker rejects diagnostics and fault injection before storage work', async () => {
  const replies = [], scope = {postMessage: message => replies.push(message)};
  installWorker({memory_bytes: () => 0}, {...options, channel: '0'.repeat(32), diagnostics: false}, scope);
  for (const action of ['tamper', 'seedFixture', 'integerCrossings', 'save_revision_diagnostic', 'publish', 'release']) {
    await scope.onmessage({data: {requestId: action, channel: '0'.repeat(32), action, args: {}}});
    assert.equal(replies.at(-1).code, 'UnsupportedCapability');
  }
  await scope.onmessage({data: {requestId: 'fault', channel: '0'.repeat(32), action: 'read', args: {fault: 'confirm'}}});
  assert.equal(replies.at(-1).code, 'InvalidInput');
  const before = replies.length;
  await scope.onmessage({data: {requestId: 'foreign', channel: '1'.repeat(32), action: 'lock', args: {}}});
  assert.equal(replies.length, before);
});

test('text credentials preserve exact UTF-8 bytes', () => {
  assert.deepEqual(passwordTextToBytes(' a\0é '), new Uint8Array([32, 97, 0, 195, 169, 32]));
  assert.notDeepEqual(passwordTextToBytes('é'), passwordTextToBytes('e\u0301'));
});
