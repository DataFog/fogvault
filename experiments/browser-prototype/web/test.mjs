// Disposable browser contract tests. Full snapshots below are test assertions on
// fixtures; the production-shaped Worker startup must never use getAll.
import {passwordTextToBytes, passwordTextArguments, wipePasswordArguments} from './password.mjs';
const encode = s => new TextEncoder().encode(s);
const equal = (a, b) => a.length === b.length && a.every((n, i) => n === b[i]);
const hex = value => [...new Uint8Array(value.buffer || value, value.byteOffset || 0, value.byteLength)].map(n => n.toString(16).padStart(2, '0')).join('');
const id = new Uint8Array(16).fill(7), request = n => new Uint8Array(16).fill(n);
const password = passwordTextToBytes('SYNTHETIC browser feasibility password');
const metadata = encode('synthetic browser metadata');
const payload = encode('SYNTHETIC vault persistence and lock proof');
const cases = [], samples = [], growth = [], owners = new Set(), databases = new Set();
const storageProfile = new URL(location.href).searchParams.get('storage') || 'blob';
const mutatingActions = new Set(['create', 'save_at', 'save_revision_diagnostic', 'delete', 'delete_at', 'publish', 'change_password', 'upgrade_kdf']);
// Smallest strictly greater pass count is an explicit experiment, not a default.
const baselineKdf = {memory_kib: 65536, passes: 3}, upgradedKdf = {memory_kib: 65536, passes: 4};
const kdfProfiles = [baselineKdf, upgradedKdf];
const newPassword = passwordTextToBytes('SYNTHETIC changed browser password');
const names = prefix => {const name = 'fogvault-PROTOTYPE-WIPE-ME-' + prefix + '-' + crypto.randomUUID(); databases.add(name); return name;};
class Owner {
  constructor() {this.epoch = 0; this.sequence = 0; this.pending = new Map(); this.progressWaiters = []; owners.add(this); this.make();}
  make() {
    this.worker = new Worker('./worker.mjs?storage=' + storageProfile, {type: 'module'});
    this.ready = new Promise((resolve, reject) => {
      this.worker.onerror = event => {const error = Error(event.message); reject(error); this.rejectPending(error);};
      this.worker.onmessage = ({data}) => {
        if (data.ready) {resolve(data); return;}
        if (data.progress) {
          this.onprogress?.(data.progress, data);
          const waiting = this.progressWaiters.filter(p => p.name === data.progress);
          this.progressWaiters = this.progressWaiters.filter(p => p.name !== data.progress);
          for (const p of waiting) p.resolve(data);
          return;
        }
        const p = this.pending.get(data.requestId); if (!p) return;
        this.pending.delete(data.requestId);
        if (p.epoch !== this.epoch) {p.reject(Error('stale-owner-epoch')); return;}
        if (data.ok) {if (['prepare_save_at', 'prepare_revision_diagnostic', 'prepare_delete', 'prepare_delete_at', 'prepare_password_change', 'prepare_kdf_upgrade'].includes(p.action)) this.preparedRequest = p.operationRequest?.slice(); if (['save_at', 'save_revision_diagnostic', 'delete', 'delete_at', 'change_password', 'upgrade_kdf', 'publish', 'lock', 'create', 'open', 'close'].includes(p.action)) this.preparedRequest = undefined; p.resolve(data);}
        else {const error = Error(typeof data.error === 'string' ? data.error : JSON.stringify(data.error)); if (data.code) error.code = data.code; if (data.request_id instanceof Uint8Array) error.request_id = data.request_id.slice(); p.reject(error);}
      };
    });
  }
  waitProgress(name) {return new Promise(resolve => this.progressWaiters.push({name, resolve}));}
  async call(action, args = {}) {
    if (['save_at', 'prepare_save_at', 'save_revision_diagnostic', 'prepare_revision_diagnostic'].includes(action) && (!(args.payload instanceof Uint8Array) || args.payload.length > 16 * 1024 * 1024 || !(args.metadata instanceof Uint8Array) || args.metadata.length > 32)) throw Error('owner-resource-policy-before-clone');
    if (['save_at', 'prepare_save_at'].includes(action)) {
      if (!(args.expected_head instanceof Uint8Array) || args.expected_head.length !== 32) throw Error('32-byte expected head required before transport');
      // Capture authority at caller admission, before rawCall can await Worker
      // readiness. A caller's later buffer mutation cannot refresh old intent.
      args = {...args, expected_head: args.expected_head.slice()};
    }
    return this.rawCall(action, args);
  }
  async callText(action, args = {}) {
    // This text adapter rejects malformed UTF-16 before message transport. Its
    // owned UTF-8 buffers are cleared after completion/error; strings remain
    // caller-owned and cannot be erased by this API.
    const converted = passwordTextArguments(action, args);
    try { return await this.call(action, converted); }
    finally { wipePasswordArguments(action, converted); }
  }
  async rawCall(action, args = {}) {
    await this.ready;
    const requestId = ++this.sequence, epoch = this.epoch;
    const operationRequest = args.request instanceof Uint8Array ? args.request.slice() : action === 'publish' ? this.preparedRequest?.slice() : undefined;
    return new Promise((resolve, reject) => {this.pending.set(requestId, {resolve, reject, epoch, action, operationRequest}); this.worker.postMessage({requestId, action, args});});
  }
  rejectPending(reason) {
    for (const pending of this.pending.values()) {
      if (mutatingActions.has(pending.action)) {
        const error = Error('mutation reply lost; commit outcome requires reconciliation'); error.code = 'OutcomeUnknown';
        if (pending.operationRequest) error.request_id = pending.operationRequest.slice(); pending.reject(error);
      } else pending.reject(reason);
    }
    this.pending.clear();
  }
  terminate() {if (!this.worker) return; this.epoch++; this.worker.terminate(); this.worker = null; this.rejectPending(Error('revoked-worker')); owners.delete(this);}

}
const integrityError = /integrity|inconsistent|authentication|committed.*missing|missing.*committed/i;
const conflictError = /conflict|stale.*head|accepted.head/i;
const uncertainError = /outcome.*unknown|uncertain|reconcil|requires.*reopen/i;
async function expectReject(promise, pattern) {try {await promise;} catch (error) {if (pattern && !pattern.test(String(error) + ' ' + (error.code || ''))) throw error; return error;} throw Error('operation unexpectedly succeeded');}
async function record(name, run) {const start = performance.now(); try {const evidence = await run(); cases.push({id: name, status: 'pass', executed: true, elapsed_ms: performance.now() - start, ...evidence});} catch (error) {cases.push({id: name, status: 'fail', executed: true, error: String(error), elapsed_ms: performance.now() - start}); throw error;}}
async function sample(owner, action, args = {}) {const response = await owner.call(action, args); samples.push({operation: action, elapsed_ms: response.elapsed_ms, memory_bytes: response.result.memory_bytes ?? null}); return response.result;}
const saveArgs = (revision = 1, number = 2, data = encode('replacement')) => ({id, expected: revision, metadata, payload: data, request: request(number)});
const receipt = value => value.receipt || value;
const equalReceipt = (first, second) => {first = receipt(first); second = receipt(second); return first.generation === second.generation && equal(first.request_id, second.request_id) && equal(first.head_digest, second.head_digest);};
async function fresh(prefix, seeded = true, maxRecords = 4096, profiles) {const name = names(prefix), owner = new Owner(); await owner.call('create', {name, password, max_records: maxRecords, kdf_profiles: profiles}); if (seeded) await owner.call('save_revision_diagnostic', saveArgs(0, 1, payload)); return {name, owner, maxRecords};}
async function reopen(name, maxRecords = 4096, credential = password, profiles) {const owner = new Owner(); await owner.call('open', {name, max_records: maxRecords, kdf_profiles: profiles}); await owner.call('unlock', {password: credential}); return owner;}
function headerOnlyWrites(value, replay = false) {if (!value.writes || value.writes.state !== (replay ? 0 : 1) || value.writes.records !== 0 || value.writes.nodes !== 0) throw Error('credential mutation rewrote record/index objects or replay wrote state');}
async function sameCiphertextStores(name, before) {const after = await snapshotDatabase(name); const objects = value => value.stores.filter(store => store.store !== 'state'); if (JSON.stringify(objects(before)) !== JSON.stringify(objects(after))) throw Error('credential update changed record/index ciphertext');}
const kdfError = /resource|policy|cost|parameter|upgrade|downgrade|admission|profile|InvalidInput|Malformed/i;
function requestResult(r) {return new Promise((resolve, reject) => {r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error);});}
function completion(tx) {return new Promise((resolve, reject) => {tx.oncomplete = resolve; tx.onabort = () => reject(tx.error || Error('aborted test transaction')); tx.onerror = () => {};});}
async function rawDatabase(name, version, upgrade) {const r = version === undefined ? indexedDB.open(name) : indexedDB.open(name, version); if (upgrade) r.onupgradeneeded = event => upgrade(r.result, r.transaction, event); return requestResult(r);}
async function normalized(value) {
  if (value instanceof Blob) return {bytes: hex(new Uint8Array(await value.arrayBuffer()))};
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return {bytes: hex(value)};
  if (typeof value === 'bigint') return {bigint: value.toString()};
  if (Array.isArray(value)) return Promise.all(value.map(normalized));
  if (value && typeof value === 'object') {const output = {}; for (const name of Object.keys(value).sort()) output[name] = await normalized(value[name]); return output;}
  return value;
}
async function snapshotDatabase(name, raw = false) {
  const db = await rawDatabase(name), stores = [...db.objectStoreNames].sort();
  const tx = db.transaction(stores, 'readonly'), done = completion(tx);
  const data = await Promise.all(stores.map(async store => {const object = tx.objectStore(store); const [keys, values] = await Promise.all([requestResult(object.getAllKeys()), requestResult(object.getAll())]); return {store, keys, values};}));
  await done; const version = db.version; db.close(); return {version, stores: raw ? data : await normalized(data)};
}
async function sameDatabase(name, before, ignoreVersion = false) {const after = await snapshotDatabase(name); if (JSON.stringify(ignoreVersion ? before.stores : before) !== JSON.stringify(ignoreVersion ? after.stores : after)) throw Error('persistent state changed unexpectedly');}
// Binary comparisons keep the 16 MiB rejection fixture exact without expanding
// every encrypted byte into a JavaScript hex string. These snapshots are tests.
async function exactStoredEqual(first, second) {
  if (Object.is(first, second)) return true;
  if (first instanceof Blob || second instanceof Blob) {
    if (!(first instanceof Blob) || !(second instanceof Blob) || first.size !== second.size || first.type !== second.type) return false;
    return equal(new Uint8Array(await first.arrayBuffer()), new Uint8Array(await second.arrayBuffer()));
  }
  if (first instanceof ArrayBuffer || second instanceof ArrayBuffer || ArrayBuffer.isView(first) || ArrayBuffer.isView(second)) {
    if (!(first instanceof ArrayBuffer || ArrayBuffer.isView(first)) || !(second instanceof ArrayBuffer || ArrayBuffer.isView(second)) || first.constructor !== second.constructor || first.byteLength !== second.byteLength || first.byteOffset !== second.byteOffset) return false;
    return equal(new Uint8Array(first.buffer || first, first.byteOffset || 0, first.byteLength), new Uint8Array(second.buffer || second, second.byteOffset || 0, second.byteLength));
  }
  if (!first || !second || typeof first !== 'object' || typeof second !== 'object') return false;
  if (Array.isArray(first) !== Array.isArray(second)) return false;
  const firstKeys = Object.keys(first).sort(), secondKeys = Object.keys(second).sort();
  if (!equal(firstKeys, secondKeys)) return false;
  for (const key of firstKeys) if (!await exactStoredEqual(first[key], second[key])) return false;
  return true;
}
async function sameBinaryDatabase(name, before) {
  if (!await exactStoredEqual(before, await snapshotDatabase(name, true))) throw Error('persistent binary state changed unexpectedly');
}
async function editDatabase(name, action) {const db = await rawDatabase(name); const tx = db.transaction([...db.objectStoreNames], 'readwrite'), done = completion(tx); action(tx); await done; db.close();}
async function rawRecord(name, identity = id) {
  const db = await rawDatabase(name), tx = db.transaction(['state', 'records', 'nodes'], 'readonly'), done = completion(tx);
  let state, row, hash, node;
  const stateRequest = tx.objectStore('state').get('current');
  stateRequest.onsuccess = () => {state = stateRequest.result; hash = hex(state.head.slice(65, 97)); const next = tx.objectStore('nodes').get(hash); next.onsuccess = () => {node = next.result;};};
  const rowRequest = tx.objectStore('records').get(hex(identity)); rowRequest.onsuccess = () => {row = rowRequest.result;};
  await done; db.close(); return {state, row, hash, node};
}
async function missingDatabase(name) {const r = indexedDB.open(name); let created = false; r.onupgradeneeded = event => {if (event.oldVersion === 0) {created = true; r.transaction.abort();}}; return new Promise((resolve, reject) => {r.onsuccess = () => {r.result.close(); resolve(false);}; r.onerror = () => created ? resolve(true) : reject(r.error);});}

const name = names('original-flow'); let owner = new Owner();
window.fogvaultDone = (async () => {
  try {
    let ticks = 0, duringKdf = false, kdfStartedAt = null, kdfFinishedAt = null;
    owner.onprogress = progress => {if (progress === 'kdf-started') {duringKdf = true; kdfStartedAt = performance.now();} if (progress === 'kdf-finished') {duringKdf = false; kdfFinishedAt = performance.now();}};
    const interval = setInterval(() => {if (duringKdf) ticks++;}, 0);
    await sample(owner, 'create', {name, password}); clearInterval(interval); owner.onprogress = null;
    await record('worker_kdf_keeps_main_event_loop_running', async () => {if (ticks === 0) throw Error('no main-thread timer progress during Worker KDF'); return {timer_callbacks: ticks, observed_ms: kdfFinishedAt - kdfStartedAt};});
    await record('indexeddb_create_save_lock_worker_reopen_read', async () => {await sample(owner, 'save_revision_diagnostic', saveArgs(0, 1, payload)); await sample(owner, 'lock'); await expectReject(owner.call('read', {id}), /locked/i); owner.terminate(); owner = new Owner(); await owner.call('open', {name}); await sample(owner, 'unlock', {password}); const got = await sample(owner, 'read', {id}); if (!equal(got.payload, payload) || !equal(got.metadata, metadata) || got.revision !== 1n) throw Error('roundtrip mismatch'); return {separate_worker: true};});
    await record('current_format_epoch_zero_is_used_by_browser_storage', async () => {
      const stored = await rawRecord(name), descriptor = stored.state.descriptor;
      const envelope = new Uint8Array(stored.row.envelope instanceof Blob ? await stored.row.envelope.arrayBuffer() : stored.row.envelope.slice(0));
      const d = new DataView(descriptor.buffer, descriptor.byteOffset, descriptor.byteLength), e = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
      if (descriptor.length !== 180 || !equal(descriptor.slice(0, 8), encode('FGVP0003')) || d.getUint16(12) !== 3 || d.getBigUint64(30) !== 0n) throw Error('current browser creation profile drift');
      if (!equal(envelope.slice(0, 8), encode('FGVR0003')) || e.getBigUint64(32) !== 0n || envelope.length !== payload.length + metadata.length + 176) throw Error('current browser record framing drift');
      await owner.call('lock');
      const legacy = descriptor.slice(); legacy[13] = 2;
      await editDatabase(name, tx => tx.objectStore('state').put({...stored.state, descriptor: legacy}, 'current'));
      await expectReject(owner.call('unlock', {password}), /unsupported|legacy|format/i);
      const rejected = await rawRecord(name);
      if (!equal(rejected.state.descriptor, legacy)) throw Error('legacy refusal modified stored descriptor');
      await editDatabase(name, tx => tx.objectStore('state').put(stored.state, 'current'));
      await owner.call('unlock', {password});
      return {credential_format: 3, content_format: 3, root_epoch: '0', record_overhead: 176, legacy_open_refused_without_migration: true};
    });
    await record('wrong_password_does_not_publish_authority', async () => {await owner.call('lock'); await expectReject(owner.call('unlock', {password: encode('wrong')}), /authentication/i); await expectReject(owner.call('read', {id}), /locked/i); await sample(owner, 'unlock', {password}); return {};});
    await record('indexeddb_abort_preserves_previous_commit', async () => {const before = await snapshotDatabase(name); await expectReject(owner.call('save_revision_diagnostic', {...saveArgs(), abort: true}), /abort/i); await sameDatabase(name, before); const got = await sample(owner, 'read', {id}); if (!equal(got.payload, payload)) throw Error('old content lost'); return {all_stores_unchanged: true};});
    await record('lock_revokes_prepared_delayed_publication', async () => {const before = await snapshotDatabase(name); await owner.call('prepare_revision_diagnostic', saveArgs(1, 3)); await owner.call('lock'); await expectReject(owner.call('publish'), /stale.prepared|locked/i); await sameDatabase(name, before); await sample(owner, 'unlock', {password}); return {};});
    await record('lock_revokes_delayed_unlock_authority', async () => {const waiting = owner.waitProgress('unlock-snapshot-waiting'); const unlock = owner.call('unlock', {password, barrier: true}); const rejected = expectReject(unlock, /stale.unlock|locked|abort/i); await waiting; await owner.call('lock'); await rejected; await expectReject(owner.call('read', {id}), /locked/i); await sample(owner, 'unlock', {password}); return {barrier: 'private unlock candidate waits before authority publication; lock wins'};});
    await record('worker_termination_discards_inflight_unlock_result', async () => {await owner.call('lock'); const started = owner.waitProgress('kdf-started'); const unlock = owner.call('unlock', {password}); const rejected = expectReject(unlock, /revoked.worker/); await started; owner.terminate(); await rejected; owner = new Owner(); await owner.call('open', {name}); await expectReject(owner.call('read', {id}), /locked/i); await sample(owner, 'unlock', {password}); return {cancellation: 'worker terminated; no zeroization-finalizer claim'};});
    await record('core_16mib_opaque_payload_roundtrip', async () => {const big = new Uint8Array(16 * 1024 * 1024); for (let i = 0; i < big.length; i += 65536) crypto.getRandomValues(big.subarray(i, i + 65536)); const started = performance.now(); await sample(owner, 'save_revision_diagnostic', saveArgs(1, 4, big)); await sample(owner, 'lock'); owner.terminate(); owner = new Owner(); await owner.call('open', {name}); await sample(owner, 'unlock', {password}); const got = await sample(owner, 'read', {id}); if (got.payload.length !== big.length || !equal(got.payload, big) || got.revision !== 2n) throw Error('16MiB mismatch'); return {payload_bytes: big.length, roundtrip_ms: performance.now() - started, wasm_linear_memory_bytes: got.memory_bytes};});
    await record('u64_revision_crossing_preserves_all_bits', async () => {
      const crossings = (await owner.call('integerCrossings')).result;
      if (crossings.direct_binding_range_rejection !== true || crossings.out_of_range_revision_inputs_rejected !== true) throw Error('direct Rust binding range rejection was not observed');
      const before = await snapshotDatabase(name, true);
      for (const expected of [-1n, 9223372036854775808n, 18446744073709551618n, '2']) {
        await expectReject(owner.call('save_revision_diagnostic', saveArgs(expected, 6, payload)), /revision|InvalidInput|Malformed|range|type|expected/i);
        await sameBinaryDatabase(name, before);
      }
      return {...crossings, out_of_range_revision_inputs_rejected: true, direct_binding_range_rejection: true, invalid_expected_saves: 4, persistent_bytes_unchanged: true};
    });
    await record('oversized_input_rejected_before_wasm_copy', async () => {const before = await owner.call('inspect'); for (const value of [{metadata, payload: new Uint8Array(16 * 1024 * 1024 + 1)}, {metadata: new Uint8Array(33), payload}, {metadata, payload: [1, 2, 3]}]) {const args = {id, expected: 2, request: request(5), ...value}; await expectReject(owner.call('save_revision_diagnostic', args), /owner.resource.policy.before.clone/); await expectReject(owner.rawCall('save_revision_diagnostic', args), /resource.policy.before.wasm.copy/);} const after = await owner.call('inspect'); if (!equal(before.result.head, after.result.head) || before.result.memory_bytes !== after.result.memory_bytes) throw Error('admission changed head or grew WASM extent'); return {admission: 'owner before structured clone and Worker before WASM copies', head_unchanged: true, wasm_extent_unchanged: true};});
    await record('ciphertext_tamper_rejects_before_plaintext', async () => {await owner.call('tamper', {id}); await expectReject(owner.call('read', {id}), integrityError); return {};});
    await owner.call('close'); owner.terminate();

    await record('exclusive_create_and_missing_open_are_non_destructive', async () => {
      const fixture = await fresh('exclusive'), before = await snapshotDatabase(fixture.name), other = new Owner();
      await expectReject(other.call('create', {name: fixture.name, password}), /exist|Constraint/i); await sameDatabase(fixture.name, before); other.terminate();
      const absent = names('absent'), missing = new Owner(); await expectReject(missing.call('open', {name: absent}), /not.?found|missing/i);
      if (!await missingDatabase(absent)) throw Error('opening missing store initialized a database'); missing.terminate();
      const incomplete = await fresh('occupied-incomplete', false);
      await editDatabase(incomplete.name, tx => tx.objectStore('state').delete('current'));
      const occupied = await snapshotDatabase(incomplete.name), replacement = new Owner();
      await expectReject(replacement.call('create', {name: incomplete.name, password}), /exist|incomplete|missing.state|integrity|unsupported/i);
      await sameDatabase(incomplete.name, occupied); replacement.terminate(); incomplete.owner.terminate(); fixture.owner.terminate();
      return {existing_bytes_preserved: true, missing_database_not_created: true, occupied_incomplete_not_initialized: true};
    });
    await record('unsupported_browser_schema_is_not_migrated', async () => {const legacyName = names('legacy'); const legacy = await rawDatabase(legacyName, 1, db => db.createObjectStore('unrelated')); const tx = legacy.transaction('unrelated', 'readwrite'), done = completion(tx); tx.objectStore('unrelated').put('SYNTHETIC preserve me', 'sentinel'); await done; legacy.close(); const before = await snapshotDatabase(legacyName), old = new Owner(); await expectReject(old.call('open', {name: legacyName}), /schema|version|unsupported/i); old.terminate(); await sameDatabase(legacyName, before); return {legacy_version: 1, unchanged: true};});
    await record('latest_retry_is_zero_write_and_reused_id_rejects_changes', async () => {
      const fixture = await fresh('retry'), first = (await fixture.owner.call('save_revision_diagnostic', saveArgs())).result, before = await snapshotDatabase(fixture.name);
      const retried = (await fixture.owner.call('save_revision_diagnostic', saveArgs())).result;
      if (!equalReceipt(first, retried)) throw Error('retry receipt changed'); await sameDatabase(fixture.name, before);
      await expectReject(fixture.owner.call('save_revision_diagnostic', saveArgs(1, 2, encode('different input'))), /request.*reuse|OperationIdReuse|different.*content/i); await sameDatabase(fixture.name, before);
      await fixture.owner.call('prepare_revision_diagnostic', saveArgs());
      const writer = await reopen(fixture.name); await writer.call('save_revision_diagnostic', saveArgs(2, 3));
      await expectReject(fixture.owner.call('publish'), conflictError);
      await writer.call('prepare_revision_diagnostic', saveArgs(2, 3));
      await editDatabase(fixture.name, tx => tx.objectStore('records').delete(hex(id)));
      const missing = await snapshotDatabase(fixture.name);
      await expectReject(writer.call('publish'), integrityError); await sameDatabase(fixture.name, missing);
      fixture.owner.terminate(); writer.terminate();
      return {receipt_equal: true, persistent_bytes_unchanged: true, stale_retry_publish_rejected: true, missing_target_retry_publish_rejected: true};
    });
    await record('uncertain_commit_blocks_use_until_metadata_reconciliation', async () => {const fixture = await fresh('uncertain'); await expectReject(fixture.owner.call('save_revision_diagnostic', {...saveArgs(), lostAck: true}), uncertainError); await expectReject(fixture.owner.call('read', {id}), uncertainError); await expectReject(fixture.owner.call('save_revision_diagnostic', saveArgs(2, 3)), uncertainError); const recovered = receipt((await fixture.owner.call('reconcile_latest', {request: request(2)})).result); if (recovered.generation !== 2n || !equal(recovered.request_id, request(2))) throw Error('wrong recovered receipt'); const got = (await fixture.owner.call('read', {id})).result; if (got.revision !== 2n || !equal(got.payload, encode('replacement'))) throw Error('reconciled value mismatch'); fixture.owner.terminate(); return {committed_generation: '2', further_use_blocked: true};});
    await record('uncertain_reconciliation_rejects_missing_committed_content', async () => {const fixture = await fresh('uncertain-integrity'); await expectReject(fixture.owner.call('save_revision_diagnostic', {...saveArgs(), lostAck: true}), uncertainError); const saved = await rawRecord(fixture.name); await editDatabase(fixture.name, tx => tx.objectStore('records').delete(hex(id))); await expectReject(fixture.owner.call('reconcile_latest', {request: request(2)}), integrityError); await editDatabase(fixture.name, tx => tx.objectStore('records').put(saved.row, hex(id))); await editDatabase(fixture.name, tx => tx.objectStore('nodes').delete(saved.hash)); await expectReject(fixture.owner.call('reconcile_latest', {request: request(2)}), integrityError); await editDatabase(fixture.name, tx => tx.objectStore('nodes').put(saved.node, saved.hash)); await fixture.owner.call('reconcile_latest', {request: request(2)}); fixture.owner.terminate(); return {missing_record_rejected: true, missing_node_rejected: true, same_worker_recovery_after_failed_audit: true};});
    await record('reopen_recovers_latest_receipt_and_superseded_receipts_reject', async () => {
      const fixture = await fresh('reopen-receipt'), waiting = fixture.owner.waitProgress('postcommit-paused');
      const saving = fixture.owner.call('save_revision_diagnostic', {...saveArgs(), pause: 'postcommit'});
      const rejected = expectReject(saving, uncertainError); await waiting; fixture.owner.terminate();
      const transport = await rejected;
      if (transport.code !== 'OutcomeUnknown' || !equal(transport.request_id, request(2))) throw Error('mutating transport loss lost its uncertain outcome/request identity');
      const reopened = await reopen(fixture.name), recovered = receipt((await reopened.call('reconcile_latest', {request: request(2)})).result), state = (await rawRecord(fixture.name)).state;
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', state.head));
      if (recovered.generation !== 2n || !equal(recovered.head_digest, digest)) throw Error('reopened receipt not bound to committed head');
      const third = receipt((await reopened.call('save_revision_diagnostic', saveArgs(2, 3))).result);
      await expectReject(reopened.call('reconcile_latest', {request: request(2)}), /not.?found|latest|superseded|conflict/i);
      const latest = (await reopened.call('reconcile_latest', {request: request(3)})).result;
      if (!equalReceipt(third, latest)) throw Error('latest receipt changed'); reopened.terminate();
      return {reopened_latest_recovered: true, historical_receipt_not_claimed: true, postcommit_worker_loss_reconciled: true, transport_error_code: transport.code, transport_request_id_preserved: true};
    });
    await record('synchronous_storage_fault_rolls_back_all_stores', async () => {
      const fixture = await fresh('storage-fault');
      for (const fault of ['quota', 'clone']) {
        const before = await snapshotDatabase(fixture.name);
        await expectReject(fixture.owner.call('save_revision_diagnostic', {...saveArgs(), fault}), fault === 'quota' ? /quota|capacity/i : /clone/i);
        await sameDatabase(fixture.name, before);
        if (!equal((await fixture.owner.call('read', {id})).result.payload, payload)) throw Error('storage fault lost old plaintext');
      }
      await fixture.owner.call('prepare_revision_diagnostic', saveArgs());
      const stored = await rawRecord(fixture.name), changed = new Uint8Array(stored.row.envelope instanceof Blob ? await stored.row.envelope.arrayBuffer() : stored.row.envelope.slice(0));
      changed[changed.length - 1] ^= 1;
      const tampered = {...stored.row, envelope: storageProfile === 'blob' ? new Blob([changed]) : changed.buffer};
      await editDatabase(fixture.name, tx => tx.objectStore('records').put(tampered, hex(id)));
      const corrupted = await snapshotDatabase(fixture.name);
      await expectReject(fixture.owner.call('publish'), integrityError); await sameDatabase(fixture.name, corrupted);
      fixture.owner.terminate();
      return {faults: ['QuotaExceededError', 'DataCloneError'], injected_request_errors: true, actual_quota_exhaustion_claimed: false, same_length_tamper_after_prepare_rejected: true};
    });
    await record('lock_revokes_precommit_publication', async () => {const fixture = await fresh('precommit-lock'), before = await snapshotDatabase(fixture.name), waiting = fixture.owner.waitProgress('precommit-paused'); const save = fixture.owner.call('save_revision_diagnostic', {...saveArgs(), pause: 'precommit'}), rejected = expectReject(save, /revok|stale|locked|abort/i); await waiting; await fixture.owner.call('lock'); await rejected; await sameDatabase(fixture.name, before); await expectReject(fixture.owner.call('read', {id}), /locked/i); fixture.owner.terminate(); return {publication_revoked: true, bytes_unchanged: true};});
    await record('two_writers_use_accepted_head_compare_and_swap', async () => {const fixture = await fresh('writers'), other = await reopen(fixture.name); await fixture.owner.call('prepare_revision_diagnostic', saveArgs(1, 2, encode('first writer'))); await other.call('prepare_revision_diagnostic', saveArgs(1, 3, encode('second writer'))); const outcomes = await Promise.allSettled([fixture.owner.call('publish'), other.call('publish')]); if (outcomes.filter(value => value.status === 'fulfilled').length !== 1 || outcomes.filter(value => value.status === 'rejected').length !== 1) throw Error('CAS did not choose exactly one writer'); const failure = outcomes.find(value => value.status === 'rejected').reason; if (!conflictError.test(String(failure) + ' ' + (failure.code || ''))) throw failure; const current = await reopen(fixture.name); if ((await current.call('read', {id})).result.revision !== 2n) throw Error('CAS winner revision incorrect'); fixture.owner.terminate(); other.terminate(); current.terminate(); return {successful_writers: 1, rejected_writers: 1};});
    await record('startup_readonly_snapshot_orders_concurrent_writer', async () => {const fixture = await fresh('startup-snapshot'); await fixture.owner.call('prepare_revision_diagnostic', saveArgs()); const reader = new Owner(); await reader.call('open', {name: fixture.name}); const paused = reader.waitProgress('startup-paused'), unlocking = reader.call('unlock', {password, pause: 'startup'}); await paused; const requested = fixture.owner.waitProgress('publish-transaction-opened'), publishing = fixture.owner.call('publish'); await requested; await reader.call('release', {barrier: 'startup'}); const unlocked = (await unlocking).result; await publishing; await expectReject(reader.call('read', {id}), conflictError); if ((unlocked.stats?.records_checked ?? unlocked.stats?.records) !== 1) throw Error('startup snapshot did not validate one committed record'); fixture.owner.terminate(); reader.terminate(); return {snapshot_records: 1, competing_writer_requested_while_readonly_active: true};});
    await record('point_read_snapshot_survives_concurrent_path_retirement', async () => {const fixture = await fresh('read-snapshot'), reader = await reopen(fixture.name), old = await rawRecord(fixture.name); const paused = reader.waitProgress('read-captured-paused'), reading = reader.call('read', {id, pause: 'read-captured'}); await paused; await fixture.owner.call('save_revision_diagnostic', saveArgs()); const current = await rawRecord(fixture.name); if (current.hash === old.hash) throw Error('updated record retained old leaf unexpectedly'); const raw = await rawDatabase(fixture.name), tx = raw.transaction('nodes', 'readonly'), done = completion(tx), retired = await requestResult(tx.objectStore('nodes').get(old.hash)); await done; raw.close(); if (retired !== undefined) throw Error('old path was not actually retired'); await reader.call('release', {barrier: 'read-captured'}); const got = (await reading).result; if (got.revision !== 1n || !equal(got.payload, payload)) throw Error('captured snapshot did not preserve old content'); await expectReject(reader.call('read', {id}), conflictError); fixture.owner.terminate(); reader.terminate(); return {captured_revision: '1', current_revision: '2', obsolete_node_removed: true};});
    await record('streaming_startup_detects_missing_extra_and_corrupt_membership', async () => {const fixture = await fresh('stream-integrity'), original = await rawRecord(fixture.name), orphan = hex(new Uint8Array(16).fill(99)); await fixture.owner.call('lock');
      await editDatabase(fixture.name, tx => {tx.objectStore('records').delete(hex(id)); tx.objectStore('records').put(original.row, orphan);}); await expectReject(fixture.owner.call('unlock', {password}), integrityError); await expectReject(fixture.owner.call('read', {id}), /locked/i); await editDatabase(fixture.name, tx => {tx.objectStore('records').delete(orphan); tx.objectStore('records').put(original.row, hex(id));});
      const extraNode = hex(new Uint8Array(32).fill(99)); await editDatabase(fixture.name, tx => tx.objectStore('nodes').put(new Uint8Array([255]).buffer, extraNode)); await expectReject(fixture.owner.call('unlock', {password}), integrityError); await editDatabase(fixture.name, tx => tx.objectStore('nodes').delete(extraNode));
      const corrupt = new Uint8Array(original.node instanceof ArrayBuffer ? original.node.slice(0) : await original.node.arrayBuffer()); corrupt[corrupt.length - 1] ^= 1; await editDatabase(fixture.name, tx => tx.objectStore('nodes').put(corrupt.buffer, original.hash)); await expectReject(fixture.owner.call('unlock', {password}), integrityError); await editDatabase(fixture.name, tx => tx.objectStore('nodes').put(original.node, original.hash)); await fixture.owner.call('unlock', {password}); fixture.owner.terminate(); return {same_count_substitution_rejected: true, orphan_node_rejected: true, committed_node_corruption_rejected: true};});
    await record('versionchange_revokes_session_and_closes_connection', async () => {const fixture = await fresh('versionchange'), before = await snapshotDatabase(fixture.name), changed = fixture.owner.waitProgress('versionchange'); const upgraded = rawDatabase(fixture.name, 3); await changed; const db = await upgraded; db.close(); await expectReject(fixture.owner.call('read', {id}), /locked|closed|version/i); await sameDatabase(fixture.name, before, true); fixture.owner.terminate(); return {connection_closed: true, authority_revoked: true, old_stores_preserved: true};});

    await record('password_change_rewraps_only_header_and_revokes_old_password', async () => {
      const fixture = await fresh('password-change'), before = await snapshotDatabase(fixture.name);
      await expectReject(fixture.owner.call('change_password', {password: encode('wrong old password'), new_password: newPassword, request: request(90)}), /authentication/i);
      await sameDatabase(fixture.name, before);
      if (!equal((await fixture.owner.call('read', {id})).result.payload, payload)) throw Error('failed change revoked accepted session');
      const first = (await fixture.owner.call('change_password', {password, new_password: newPassword, request: request(90)})).result;
      headerOnlyWrites(first); await sameCiphertextStores(fixture.name, before);
      if ((await fixture.owner.call('read', {id})).result.revision !== 1n) throw Error('password change changed record revision');
      await fixture.owner.call('lock'); await expectReject(fixture.owner.call('unlock', {password}), /authentication/i);
      await fixture.owner.call('unlock', {password: newPassword}); fixture.owner.terminate();
      const reopened = await reopen(fixture.name, 4096, newPassword), committed = await snapshotDatabase(fixture.name);
      const retry = (await reopened.call('change_password', {password, new_password: newPassword, request: request(90)})).result;
      if (!retry.replay || !equalReceipt(first, retry)) throw Error('password retry did not return original receipt');
      headerOnlyWrites(retry, true); await sameDatabase(fixture.name, committed);
      await expectReject(reopened.call('change_password', {password: newPassword, new_password: encode('different new credential'), request: request(90)}), /reuse|OperationIdReuse/i);
      await sameDatabase(fixture.name, committed);
      if (!equal((await reopened.call('read', {id})).result.payload, payload)) throw Error('new password reopen lost content');
      reopened.terminate();
      return {record_and_index_bytes_unchanged: true, record_and_index_write_calls: 0, old_password_rejected: true, new_password_reopened: true, wrong_old_password_preserves_authority: true, latest_retry_zero_writes: true};
    });
    await record('kdf_upgrade_requires_explicit_policy_and_preserves_ciphertext', async () => {
      const fixture = await fresh('kdf-upgrade', true, 4096, kdfProfiles), before = await snapshotDatabase(fixture.name);
      const memoryBefore = (await fixture.owner.call('inspect')).result.memory_bytes;
      await expectReject(fixture.owner.call('upgrade_kdf', {password, target: {memory_kib: 65536, passes: 5}, request: request(91)}), kdfError);
      await sameDatabase(fixture.name, before);
      if ((await fixture.owner.call('inspect')).result.memory_bytes !== memoryBefore) throw Error('unadmitted KDF grew WASM extent');
      for (const memory_kib of [-1, 4294967296, 65536.5, '65536']) {
        await expectReject(fixture.owner.call('upgrade_kdf', {password, target: {memory_kib, passes: 4}, request: request(91)}), kdfError);
        await sameDatabase(fixture.name, before);
      }
      const first = (await fixture.owner.call('upgrade_kdf', {password, target: upgradedKdf, request: request(91)})).result;
      headerOnlyWrites(first); await sameCiphertextStores(fixture.name, before);
      const current = (await rawRecord(fixture.name)).state;
      if (new DataView(current.descriptor.buffer, current.descriptor.byteOffset, current.descriptor.byteLength).getUint32(77) !== 4) throw Error('upgraded pass count not persisted');
      const upgraded = await snapshotDatabase(fixture.name);
      await expectReject(fixture.owner.call('upgrade_kdf', {password, target: baselineKdf, request: request(92)}), kdfError);
      await expectReject(fixture.owner.call('upgrade_kdf', {password, target: upgradedKdf, request: request(92)}), kdfError);
      await sameDatabase(fixture.name, upgraded); fixture.owner.terminate();
      const baselineOnly = new Owner(); await baselineOnly.call('open', {name: fixture.name});
      await expectReject(baselineOnly.call('unlock', {password}), kdfError); await expectReject(baselineOnly.call('read', {id}), /locked/i); baselineOnly.terminate();
      const reopened = await reopen(fixture.name, 4096, password, kdfProfiles);
      const retry = (await reopened.call('upgrade_kdf', {password, target: upgradedKdf, request: request(91)})).result;
      if (!retry.replay || !equalReceipt(first, retry)) throw Error('KDF retry receipt changed');
      headerOnlyWrites(retry, true); await sameDatabase(fixture.name, upgraded);
      if (!equal((await reopened.call('read', {id})).result.payload, payload)) throw Error('upgraded reopen lost content');
      reopened.terminate();
      return {explicit_host_policy: true, unadmitted_target_rejected_before_work: true, invalid_numeric_profiles_rejected: 4, rejected_target_wasm_extent_unchanged: true, downgrade_and_noop_rejected: true, record_and_index_bytes_unchanged: true, record_and_index_write_calls: 0, baseline_open_rejects_upgrade: true, latest_retry_zero_writes: true};
    });
    await record('credential_abort_and_unknown_outcome_preserve_publication_contract', async () => {
      const fixture = await fresh('credential-outcomes', true, 4096, kdfProfiles), before = await snapshotDatabase(fixture.name);
      await expectReject(fixture.owner.call('change_password', {password, new_password: newPassword, request: request(93), abort: true}), /abort/i);
      await sameDatabase(fixture.name, before);
      for (const fault of ['quota', 'clone']) {
        await expectReject(fixture.owner.call('upgrade_kdf', {password, target: upgradedKdf, request: request(93), fault}), fault === 'quota' ? /quota|capacity/i : /clone/i);
        await sameDatabase(fixture.name, before);
      }
      await expectReject(fixture.owner.call('change_password', {password, new_password: newPassword, request: request(94), lostAck: true}), uncertainError);
      await expectReject(fixture.owner.call('read', {id}), uncertainError);
      await expectReject(fixture.owner.call('upgrade_kdf', {password: newPassword, target: upgradedKdf, request: request(95)}), uncertainError);
      await fixture.owner.call('reconcile_latest', {request: request(94)});
      await sameCiphertextStores(fixture.name, before);
      if (!equal((await fixture.owner.call('read', {id})).result.payload, payload)) throw Error('password reconciliation lost records');
      await expectReject(fixture.owner.call('upgrade_kdf', {password: newPassword, target: upgradedKdf, request: request(95), lostAck: true}), uncertainError);
      await expectReject(fixture.owner.call('read', {id}), uncertainError);
      await fixture.owner.call('reconcile_latest', {request: request(95)});
      await sameCiphertextStores(fixture.name, before); fixture.owner.terminate();
      const reopened = await reopen(fixture.name, 4096, newPassword, kdfProfiles);
      if (!equal((await reopened.call('read', {id})).result.payload, payload)) throw Error('reconciled credential header did not reopen');
      reopened.terminate();
      const confirmation = await fresh('credential-confirm-failure'), prior = await snapshotDatabase(confirmation.name);
      const failed = await expectReject(confirmation.owner.call('change_password', {password, new_password: newPassword, request: request(100), fault: 'confirm'}), uncertainError);
      if (failed.code !== 'OutcomeUnknown' || !equal(failed.request_id, request(100))) throw Error('postcommit confirmation failure lost uncertain request identity');
      await expectReject(confirmation.owner.call('read', {id}), uncertainError);
      await confirmation.owner.call('reconcile_latest', {request: request(100)});
      if (!equal((await confirmation.owner.call('read', {id})).result.payload, payload)) throw Error('confirmation failure reconciliation lost plaintext');
      await sameCiphertextStores(confirmation.name, prior); confirmation.owner.terminate();
      return {precommit_abort_preserved_all_stores: true, synchronous_storage_faults_preserved_all_stores: true, password_and_kdf_unknown_outcomes_blocked: true, new_descriptor_reconciliation_succeeded: true, postcommit_confirmation_failure_reconciled: true, record_and_index_bytes_unchanged: true};
    });
    await record('credential_precommit_lock_and_competing_writers_are_fenced', async () => {
      const fixture = await fresh('credential-writers'), before = await snapshotDatabase(fixture.name), other = await reopen(fixture.name);
      const firstPassword = encode('SYNTHETIC first winning credential'), secondPassword = encode('SYNTHETIC second winning credential');
      await fixture.owner.call('prepare_password_change', {password, new_password: firstPassword, request: request(96)});
      await other.call('prepare_password_change', {password, new_password: secondPassword, request: request(97)});
      const outcomes = await Promise.allSettled([fixture.owner.call('publish'), other.call('publish')]);
      if (outcomes.filter(x => x.status === 'fulfilled').length !== 1 || outcomes.filter(x => x.status === 'rejected').length !== 1) throw Error('credential CAS did not choose exactly one writer');
      const failed = outcomes.find(x => x.status === 'rejected').reason;
      if (!conflictError.test(String(failed) + ' ' + (failed.code || ''))) throw failed;
      await sameCiphertextStores(fixture.name, before); fixture.owner.terminate(); other.terminate();
      const winner = await reopen(fixture.name, 4096, outcomes[0].status === 'fulfilled' ? firstPassword : secondPassword);
      if (!equal((await winner.call('read', {id})).result.payload, payload)) throw Error('credential writer winner lost records'); winner.terminate();
      const locked = await fresh('credential-lock'), original = await snapshotDatabase(locked.name), waiting = locked.owner.waitProgress('precommit-paused');
      const changing = locked.owner.call('change_password', {password, new_password: newPassword, request: request(98), pause: 'precommit'}), rejected = expectReject(changing, /stale|revok|locked|abort/i);
      await waiting; await locked.owner.call('lock'); await rejected; await sameDatabase(locked.name, original);
      await locked.owner.call('unlock', {password}); locked.owner.terminate();
      return {successful_credential_writers: 1, stale_writer_rejected: true, precommit_lock_revoked: true, locked_change_persistent_bytes_unchanged: true};
    });
    await record('credential_worker_loss_reopens_new_header_and_latest_receipt', async () => {
      const fixture = await fresh('credential-worker-loss', true, 4096, kdfProfiles), before = await snapshotDatabase(fixture.name), waiting = fixture.owner.waitProgress('postcommit-paused');
      const changing = fixture.owner.call('upgrade_kdf', {password, target: upgradedKdf, request: request(99), pause: 'postcommit'}), rejected = expectReject(changing, uncertainError);
      await waiting; fixture.owner.terminate(); const lost = await rejected;
      if (lost.code !== 'OutcomeUnknown' || !equal(lost.request_id, request(99))) throw Error('credential transport lost outcome/request identity');
      const reopened = await reopen(fixture.name, 4096, password, kdfProfiles);
      const recovered = (await reopened.call('reconcile_latest', {request: request(99)})).result;
      const retry = (await reopened.call('upgrade_kdf', {password, target: upgradedKdf, request: request(99)})).result;
      if (!retry.replay || !equalReceipt(recovered, retry)) throw Error('reopened credential receipt mismatch');
      headerOnlyWrites(retry, true); await sameCiphertextStores(fixture.name, before); reopened.terminate();
      return {actual_postcommit_worker_termination: true, transport_request_id_preserved: true, new_descriptor_reopened: true, latest_receipt_recovered: true, replay_zero_writes: true};
    });
    const vectors = await (await fetch('../../../conformance/password-vectors.json')).json();
    if (vectors.schema !== 'fogvault-password-vectors/v1') throw Error('unsupported password-vector fixture');
    const textFor = id => { const value = vectors.text.find(value => value.id === id); if (!value) throw Error('missing text vector'); return String.fromCharCode(...value.utf16_units); };
    const bytesFor = value => Uint8Array.from(value.match(/../g) || [], byte => parseInt(byte, 16));
    await record('password_text_vectors_are_exact_and_malformed_text_rejects', async () => {
      const observed = [], encoded = new Map(), transport = new Owner(), before = transport.sequence;
      for (const vector of vectors.text) {
        const bytes = passwordTextToBytes(String.fromCharCode(...vector.utf16_units));
        if (hex(bytes) !== vector.utf8_hex) throw Error('password UTF-8 golden mismatch: ' + vector.id);
        observed.push({id: vector.id, utf8_hex: hex(bytes)}); encoded.set(vector.id, bytes);
      }
      for (const [left, right] of vectors.distinct_text_pairs) if (equal(encoded.get(left), encoded.get(right))) throw Error('password normalization/case/NUL/whitespace collision');
      for (const vector of vectors.invalid_utf16) {
        const error = await expectReject(transport.callText('create', {name: names('malformed-text'), password: String.fromCharCode(...vector.utf16_units)}), /InvalidInput/);
        if (error.code !== 'InvalidInput') throw Error('malformed text lost typed rejection');
      }
      let typeRejections = 0;
      for (const value of [undefined, null, 0, {}, [], new Uint8Array(), new String('password')]) {
        const error = await expectReject(transport.callText('create', {password: value}), /InvalidInput/);
        if (error.code !== 'InvalidInput') throw Error('text type coercion was not rejected'); typeRejections++;
      }
      // Check both fields before transport, including errors in the second field
      // after the adapter allocated the first field's owned UTF-8 buffer.
      for (const [action, fields] of Object.entries({create: ['password'], unlock: ['password'], change_password: ['password', 'new_password'], prepare_password_change: ['password', 'new_password'], upgrade_kdf: ['password'], prepare_kdf_upgrade: ['password']})) {
        for (const field of fields) await expectReject(transport.callText(action, {password: 'valid', new_password: 'valid', [field]: '\ud800'}), /InvalidInput/);
      }
      if (transport.sequence !== before) throw Error('malformed password text reached Worker transport');
      transport.terminate();
      for (const bytes of encoded.values()) bytes.fill(0);
      return {vectors: observed, invalid_utf16_ids: vectors.invalid_utf16.map(value => value.id), distinct_pairs_checked: vectors.distinct_text_pairs.length, text_type_rejections: typeRejections, all_credential_fields_checked: true, malformed_text_not_transported: true, invalid_input_errors: true};
    });
    await record('password_bytes_boundary_rejects_coercion_without_mutation', async () => {
      const fixture = await fresh('password-byte-types'), before = await snapshotDatabase(fixture.name), absent = names('invalid-password-create');
      const invalid = [null, undefined, 1, 'password', [1, 2], {length: 2, 0: 1, 1: 2}, new Uint16Array([1]), new DataView(new ArrayBuffer(1))];
      let workerRejections = 0;
      for (const value of invalid) {
        for (const [action, fields] of Object.entries({create: ['password'], unlock: ['password'], change_password: ['password', 'new_password'], prepare_password_change: ['password', 'new_password'], upgrade_kdf: ['password'], prepare_kdf_upgrade: ['password']})) {
          for (const field of fields) {
            const error = await expectReject(fixture.owner.rawCall(action, {name: absent, password, new_password: newPassword, request: request(106), target: upgradedKdf, [field]: value}), /InvalidInput/);
            if (error.code !== 'InvalidInput') throw Error('Worker password type did not preserve InvalidInput'); workerRejections++;
          }
        }
      }
      if (!await missingDatabase(absent)) throw Error('malformed create occupied a database');
      const direct = (await fixture.owner.call('passwordBoundaryChecks')).result;
      let sharedWorkerTested = false;
      if (typeof SharedArrayBuffer === 'function') {
        const shared = new Uint8Array(new SharedArrayBuffer(3)); shared.set([1, 2, 3]);
        const error = await expectReject(fixture.owner.rawCall('unlock', {password: shared}), /InvalidInput/);
        if (error.code !== 'InvalidInput' || !equal(shared, new Uint8Array([1, 2, 3]))) throw Error('rejected Worker shared input was changed');
        sharedWorkerTested = true;
      }
      await sameDatabase(fixture.name, before);
      if (!equal((await fixture.owner.call('read', {id})).result.payload, payload)) throw Error('malformed credentials revoked/changed accepted session');
      fixture.owner.terminate();
      return {...direct, worker_type_rejections: workerRejections, rejected_before_database_create: true, persistent_bytes_unchanged: true, accepted_session_preserved: true, shared_worker_rejection_executed: sharedWorkerTested};
    });
    await record('password_unicode_nul_roundtrip_and_change_preserve_exact_bytes', async () => {
      const oldId = vectors.lifecycle.old_password, newId = vectors.lifecycle.new_password;
      const oldText = textFor(oldId), newText = textFor(newId), oldBytes = bytesFor(vectors.text.find(value => value.id === oldId).utf8_hex), newBytes = bytesFor(vectors.text.find(value => value.id === newId).utf8_hex);
      const database = names('unicode-nul-password'), first = new Owner();
      await first.callText('create', {name: database, password: oldText, kdf_profiles: kdfProfiles});
      await first.call('save_revision_diagnostic', saveArgs(0, 1, payload)); await first.call('lock'); first.terminate();
      const reopened = await reopen(database, 4096, oldBytes, kdfProfiles), before = await snapshotDatabase(database);
      const changed = (await reopened.callText('change_password', {password: oldText, new_password: newText, request: request(107)})).result;
      headerOnlyWrites(changed); await sameCiphertextStores(database, before);
      const retry = (await reopened.callText('change_password', {password: oldText, new_password: newText, request: request(107)})).result;
      if (!retry.replay || !equalReceipt(changed, retry)) throw Error('Unicode text password retry differs'); headerOnlyWrites(retry, true);
      await reopened.call('lock');
      await expectReject(reopened.callText('unlock', {password: newText.normalize('NFC')}), /authentication/i);
      await reopened.call('unlock', {password: newBytes});
      await reopened.callText('upgrade_kdf', {password: newText, target: upgradedKdf, request: request(108)});
      await sameCiphertextStores(database, before); reopened.terminate();
      const last = new Owner(); await last.call('open', {name: database, kdf_profiles: kdfProfiles}); await last.callText('unlock', {password: newText});
      if (!equal((await last.call('read', {id})).result.payload, payload)) throw Error('Unicode/NUL password flow lost payload'); last.terminate();
      const rawVector = vectors.raw_bytes.find(value => value.id === vectors.lifecycle.raw_password), raw = bytesFor(rawVector.bytes_hex);
      const padded = new Uint8Array(raw.length + 2).fill(42); padded.set(raw, 1); const subarray = padded.subarray(1, raw.length + 1);
      const rawDatabase = names('raw-binary-password'), rawOwner = new Owner();
      await rawOwner.call('create', {name: rawDatabase, password: subarray}); await rawOwner.call('save_revision_diagnostic', saveArgs(0, 1, payload)); await rawOwner.call('lock'); rawOwner.terminate();
      const rawReopened = await reopen(rawDatabase, 4096, raw);
      if (!equal((await rawReopened.call('read', {id})).result.payload, payload)) throw Error('raw binary/subarray password flow changed bytes'); rawReopened.terminate();
      const emptyDatabase = names('empty-password'), emptyOwner = new Owner();
      await emptyOwner.callText('create', {name: emptyDatabase, password: ''}); await emptyOwner.call('lock'); await emptyOwner.call('unlock', {password: new Uint8Array()}); emptyOwner.terminate();
      oldBytes.fill(0); newBytes.fill(0); raw.fill(0); padded.fill(0);
      return {old_password_id: oldId, new_password_id: newId, raw_password_id: rawVector.id, unicode_nul_reopened: true, no_normalization: true, text_to_raw_and_raw_to_text_interoperate: true, record_and_index_bytes_unchanged: true, latest_text_retry_zero_writes: true, kdf_upgrade_uses_same_text_contract: true, raw_binary_subarray_reopened: true, empty_text_equals_empty_bytes: true};
    });
    await record('delete_retries_empty_root_and_reinsertion_rejects_selective_replay', async () => {
      const fixture = await fresh('delete-empty'), old = await rawRecord(fixture.name);
      const args = {id, expected: 1n, request: request(120)};
      const deleted = (await fixture.owner.call('delete', args)).result;
      const empty = (await fixture.owner.call('inspect')).result;
      if (!deleted.deleted || deleted.replay || empty.records !== 0 || empty.nodes !== 0 || empty.head[64] !== 0 || deleted.writes.state !== 1 || deleted.writes.records !== 1 || deleted.writes.nodes !== 1) throw Error('last-leaf delete did not atomically publish canonical empty state');
      const committed = await snapshotDatabase(fixture.name), retry = (await fixture.owner.call('delete', args)).result;
      if (!retry.deleted || !retry.replay || !equalReceipt(deleted, retry) || Object.values(retry.writes).some(value => value !== 0)) throw Error('delete retry changed receipt or wrote storage');
      await sameDatabase(fixture.name, committed);
      await expectReject(fixture.owner.call('delete', {...args, expected: 2n}), /OperationIdReuse|reuse/i);
      await expectReject(fixture.owner.call('save_revision_diagnostic', saveArgs(0, 120)), /OperationIdReuse|reuse/i);
      await sameDatabase(fixture.name, committed);
      fixture.owner.terminate(); const reopened = await reopen(fixture.name);
      await expectReject(reopened.call('read', {id}), /NotFound|not found/i);
      await reopened.call('begin_records'); const inventory = (await reopened.call('record_page', {maximum: 2})).result;
      if (!inventory.complete || inventory.records.length || inventory.stats.nodes_read) throw Error('empty vault did not prove empty inventory');
      const inserted = (await reopened.call('save_revision_diagnostic', saveArgs(0, 121, encode('new incarnation')))).result;
      if (inserted.receipt.generation !== deleted.receipt.generation + 1n || (await reopened.call('read', {id})).result.revision !== 1n) throw Error('reinsertion did not create a new revision-one incarnation');
      const current = await rawRecord(fixture.name);
      await editDatabase(fixture.name, tx => tx.objectStore('records').put(old.row, hex(id)));
      const replayed = await snapshotDatabase(fixture.name);
      await expectReject(reopened.call('read', {id}), integrityError);
      await expectReject(reopened.call('delete', {id, expected: 1n, request: request(122)}), integrityError);
      await sameDatabase(fixture.name, replayed);
      await editDatabase(fixture.name, tx => tx.objectStore('records').put(current.row, hex(id)));
      if (!equal((await reopened.call('read', {id})).result.payload, encode('new incarnation'))) throw Error('new incarnation was lost');
      reopened.terminate();
      return {canonical_empty_root: true, empty_reopen_and_complete_inventory: true, latest_retry_zero_writes: true, receipt_equal: true, changed_operation_rejected: true, reinsertion_revision: 1, selective_old_ciphertext_replay_rejected: true};
    });
    await record('delete_abort_unknown_lock_and_stale_intent_preserve_atomicity', async () => {
      const fixture = await fresh('delete-outcomes'), original = await snapshotDatabase(fixture.name);
      for (const options of [{abort: true}, {fault: 'clone'}, {fault: 'quota'}]) {
        await expectReject(fixture.owner.call('delete', {id, expected: 1n, request: request(123), ...options}), /NotCommitted|abort|Storage|Capacity|clone|capacity/i);
        await sameDatabase(fixture.name, original);
        if (!equal((await fixture.owner.call('read', {id})).result.payload, payload)) throw Error('known delete abort lost the accepted predecessor');
      }
      const unknown = await expectReject(fixture.owner.call('delete', {id, expected: 1n, request: request(124), lostAck: true}), uncertainError);
      if (!equal(unknown.request_id, request(124))) throw Error('delete unknown lost operation identity');
      await expectReject(fixture.owner.call('begin_records'), uncertainError);
      await expectReject(fixture.owner.call('read', {id}), uncertainError);
      const recovered = (await fixture.owner.call('reconcile_latest', {request: request(124)})).result;
      if (!equal(receipt(recovered).request_id, request(124)) || (await fixture.owner.call('inspect')).result.records !== 0) throw Error('delete reconciliation did not accept the exact empty snapshot');
      const retried = (await fixture.owner.call('delete', {id, expected: 1n, request: request(124)})).result;
      if (!retried.replay || Object.values(retried.writes).some(value => value !== 0)) throw Error('reconciled deletion retry wrote storage');
      await fixture.owner.call('save_revision_diagnostic', saveArgs(0, 125, payload));
      await expectReject(fixture.owner.call('delete', {id, expected: 1n, request: request(126), fault: 'confirm'}), uncertainError);
      await expectReject(fixture.owner.call('read', {id}), uncertainError);
      await fixture.owner.call('reconcile_latest', {request: request(126)});
      await fixture.owner.call('save_revision_diagnostic', saveArgs(0, 127, payload));
      const beforeLock = await snapshotDatabase(fixture.name);
      await fixture.owner.call('prepare_delete', {id, expected: 1n, request: request(128)});
      const paused = fixture.owner.waitProgress('precommit-paused'), publishing = fixture.owner.call('publish', {pause: 'precommit'});
      const revoked = expectReject(publishing, /stale|locked|abort/i); await paused; await fixture.owner.call('lock'); await revoked;
      await sameDatabase(fixture.name, beforeLock); await fixture.owner.call('unlock', {password});
      const competitor = await reopen(fixture.name);
      await fixture.owner.call('prepare_delete', {id, expected: 1n, request: request(129)});
      await competitor.call('delete', {id, expected: 1n, request: request(130)});
      await competitor.call('save_revision_diagnostic', saveArgs(0, 131, encode('replacement incarnation')));
      const replacement = await snapshotDatabase(fixture.name);
      await expectReject(fixture.owner.call('publish'), conflictError); await sameDatabase(fixture.name, replacement);
      if (!equal((await competitor.call('read', {id})).result.payload, encode('replacement incarnation'))) throw Error('old prepared deletion removed the reinserted record');
      fixture.owner.terminate(); competitor.terminate();
      return {known_abort_variants: 3, known_aborts_preserved_all_stores: true, unknown_blocks_use_until_reconciliation: true, latest_retry_zero_writes: true, postcommit_confirmation_failure_reconciled: true, precommit_lock_preserved_all_stores: true, old_prepared_delete_rejected_after_reinsertion: true, paired_descriptor_head_cas: true};
    });
    await record('delete_authenticates_promoted_sibling_and_predecessor_cas', async () => {
      const fixture = await fresh('delete-sibling', true, 2), other = new Uint8Array(16).fill(8);
      await fixture.owner.call('save_revision_diagnostic', {...saveArgs(0, 132, payload), id: other});
      const before = await snapshotDatabase(fixture.name, true), nodeStore = before.stores.find(value => value.store === 'nodes');
      const siblingIndex = nodeStore.values.findIndex(value => {const body = new Uint8Array(value); return body[0] === 0 && equal(body.slice(1, 17), other);});
      if (siblingIndex < 0) throw Error('two-leaf fixture sibling missing');
      const siblingKey = nodeStore.keys[siblingIndex], sibling = nodeStore.values[siblingIndex], corrupt = new Uint8Array(sibling.slice(0)); corrupt[corrupt.length - 1] ^= 1;
      await editDatabase(fixture.name, tx => tx.objectStore('nodes').put(corrupt.buffer, siblingKey));
      const corruptSibling = await snapshotDatabase(fixture.name);
      if (!equal((await fixture.owner.call('read', {id})).result.payload, payload)) throw Error('selected point path unexpectedly required sibling body');
      await expectReject(fixture.owner.call('prepare_delete', {id, expected: 1n, request: request(133)}), integrityError);
      await sameDatabase(fixture.name, corruptSibling);
      await editDatabase(fixture.name, tx => tx.objectStore('nodes').put(sibling, siblingKey));
      const plan = (await fixture.owner.call('prepare_delete', {id, expected: 1n, request: request(133)})).result;
      if (plan.path_nodes !== 3 || plan.path_nodes > 130) throw Error('delete did not capture selected path plus promoted sibling');
      await editDatabase(fixture.name, tx => tx.objectStore('nodes').put(corrupt.buffer, siblingKey));
      await expectReject(fixture.owner.call('publish'), integrityError); await sameDatabase(fixture.name, corruptSibling);
      await editDatabase(fixture.name, tx => tx.objectStore('nodes').put(sibling, siblingKey));
      const selected = await rawRecord(fixture.name);
      await fixture.owner.call('prepare_delete', {id, expected: 1n, request: request(133)});
      const envelope = new Uint8Array(selected.row.envelope instanceof Blob ? await selected.row.envelope.arrayBuffer() : selected.row.envelope.slice(0)); envelope[envelope.length - 1] ^= 1;
      await editDatabase(fixture.name, tx => tx.objectStore('records').put({...selected.row, envelope: storageProfile === 'blob' ? new Blob([envelope]) : envelope.buffer}, hex(id)));
      const changedPredecessor = await snapshotDatabase(fixture.name);
      await expectReject(fixture.owner.call('publish'), integrityError); await sameDatabase(fixture.name, changedPredecessor);
      await editDatabase(fixture.name, tx => tx.objectStore('records').put(selected.row, hex(id)));
      await fixture.owner.call('delete', {id, expected: 1n, request: request(133)});
      const promoted = (await fixture.owner.call('inspect')).result;
      if (promoted.records !== 1 || promoted.nodes !== 1 || !equal((await fixture.owner.call('read', {id: other})).result.payload, payload)) throw Error('promoted sibling did not form canonical one-leaf tree');
      await fixture.owner.call('delete', {id: other, expected: 1n, request: request(134)});
      if ((await fixture.owner.call('inspect')).result.nodes !== 0) throw Error('delete-to-empty retained live index nodes');
      fixture.owner.terminate();
      return {captured_nodes: plan.path_nodes, promoted_sibling_authenticated: true, sibling_changed_after_prepare_rejected: true, same_length_predecessor_changed_after_prepare_rejected: true, rollback_preserved_all_stores: true, canonical_promotion_and_empty_root: true};
    });
    await record('delete_worker_loss_reopens_exact_latest_receipt', async () => {
      const fixture = await fresh('delete-worker-loss');
      await fixture.owner.call('prepare_delete', {id, expected: 1n, request: request(135)});
      const paused = fixture.owner.waitProgress('postcommit-paused'), publishing = fixture.owner.call('publish', {pause: 'postcommit'});
      const lost = expectReject(publishing, uncertainError); await paused; fixture.owner.terminate(); const unknown = await lost;
      if (!equal(unknown.request_id, request(135))) throw Error('terminated deletion lost transport operation identity');
      const reopened = await reopen(fixture.name), recovered = (await reopened.call('reconcile_latest', {request: request(135)})).result;
      const state = (await reopened.call('inspect')).result;
      if (state.records || state.nodes || !equal(receipt(recovered).request_id, request(135))) throw Error('terminated deletion did not reopen exact empty snapshot and receipt');
      const before = await snapshotDatabase(fixture.name), retry = (await reopened.call('delete', {id, expected: 1n, request: request(135)})).result;
      if (!retry.replay || !equalReceipt(recovered, retry) || Object.values(retry.writes).some(value => value !== 0)) throw Error('terminated deletion retry rewrote state');
      await sameDatabase(fixture.name, before); reopened.terminate();
      return {actual_postcommit_worker_termination: true, transport_request_id_preserved: true, empty_snapshot_reopened: true, latest_receipt_recovered: true, replay_zero_writes: true};
    });
    await record('delete_source_head_rejects_revision_aba_for_queued_intent', async () => {
      const fixture = await fresh('delete-source-head'), source = (await fixture.owner.call('begin_records')).result.receipt;
      const initial = await snapshotDatabase(fixture.name);
      for (const expected_head of [new Uint8Array(31), new Uint8Array(33), 'head']) await expectReject(fixture.owner.call('delete_at', {id, expected: 1n, request: request(138), expected_head}), /InvalidInput|expected head/i);
      await expectReject(fixture.owner.call('delete_at', {id, expected: 1n, request: request(138), expected_head: new Uint8Array(32)}), conflictError);
      await sameDatabase(fixture.name, initial);
      await fixture.owner.call('delete_at', {id, expected: 1n, request: request(138), expected_head: source.head_digest});
      await fixture.owner.call('save_revision_diagnostic', saveArgs(0, 139, encode('new incarnation under the same revision')));
      fixture.owner.terminate(); const reopened = await reopen(fixture.name), current = (await reopened.call('begin_records')).result.receipt;
      if ((await reopened.call('read', {id})).result.revision !== 1n) throw Error('source-head test did not reproduce revision ABA');
      const reinserted = await snapshotDatabase(fixture.name);
      await expectReject(reopened.call('delete_at', {id, expected: 1n, request: request(140), expected_head: source.head_digest}), conflictError);
      await sameDatabase(fixture.name, reinserted);
      await expectReject(reopened.call('delete_at', {id, expected: 1n, request: request(140), expected_head: current.head_digest, lostAck: true}), uncertainError);
      const reconciled = (await reopened.call('reconcile_latest', {request: request(140)})).result;
      await expectReject(reopened.call('delete_at', {id, expected: 1n, request: request(140), expected_head: current.head_digest}), conflictError);
      const empty = await snapshotDatabase(fixture.name), retried = (await reopened.call('delete_at', {id, expected: 1n, request: request(140), expected_head: receipt(reconciled).head_digest})).result;
      if (!retried.replay || !equalReceipt(reconciled, retried) || Object.values(retried.writes).some(value => value !== 0)) throw Error('explicit current-head latest retry changed the reconciled deletion');
      await sameDatabase(fixture.name, empty); reopened.terminate();
      return {invalid_source_width_or_type_rejections: 3, source_head_checked_before_preparation: true, freshly_reopened_revision_aba_rejected: true, stale_intent_preserved_all_stores: true, unknown_reconciled_by_operation_id: true, submitted_source_cannot_be_replayed_after_commit: true, explicit_current_head_latest_retry_zero_writes: true};
    });
    await record('save_source_head_rejects_revision_aba_for_queued_intent', async () => {
      const fixture = await fresh('save-source-head'), source = (await fixture.owner.call('begin_records')).result.receipt;
      const initial = await snapshotDatabase(fixture.name);
      for (const expected_head of [undefined, null, new Uint8Array(31), new Uint8Array(33), 'head']) {
        const intent = {...saveArgs(1, 141, encode('stale queued edit')), expected_head};
        await expectReject(fixture.owner.call('save_at', intent), /expected head/i);
        await expectReject(fixture.owner.rawCall('save_at', intent), /InvalidInput|expected head/i);
      }
      await expectReject(fixture.owner.rawCall('save', saveArgs(1, 141)), /unknown.operation/i);
      await expectReject(fixture.owner.rawCall('prepare', saveArgs(1, 141)), /unknown.operation/i);
      const boundary = (await fixture.owner.call('saveHeadBoundaryChecks')).result;
      if (boundary.direct_binding_invalid_source_head_rejections !== 7 || !boundary.direct_binding_did_not_prepare_mutation) throw Error('direct WASM source-head validation was not exercised');
      await sameDatabase(fixture.name, initial);
      // The owner queues an edit before transport. Another real Worker removes
      // and reinserts the record while that externally admitted intent waits.
      const writer = await reopen(fixture.name);
      const callerHead = source.head_digest.slice(), ready = fixture.owner.ready;
      let releaseIntent; fixture.owner.ready = new Promise(resolve => { releaseIntent = resolve; });
      const rejected = expectReject(fixture.owner.call('save_at', {...saveArgs(1, 141, encode('stale queued edit')), expected_head: callerHead}), conflictError);
      await writer.call('delete_at', {id, expected: 1n, request: request(142), expected_head: source.head_digest});
      const removed = (await writer.call('begin_records')).result.receipt;
      await writer.call('save_at', {...saveArgs(0, 143, encode('new incarnation')), expected_head: removed.head_digest});
      const current = (await writer.call('begin_records')).result.receipt;
      // Refresh the original Worker's accepted session while its admitted edit
      // is still outside transport. Only the saved caller head can now reject
      // the old edit; a stale local session is not the reason for rejection.
      fixture.owner.ready = ready; await fixture.owner.call('unlock', {password});
      callerHead.set(current.head_digest); // Cannot update the admitted copy.
      const reinserted = await snapshotDatabase(fixture.name);
      releaseIntent(); fixture.owner.ready = ready; await rejected;
      await sameDatabase(fixture.name, reinserted);
      fixture.owner.terminate(); writer.terminate();
      const reopened = await reopen(fixture.name);
      await expectReject(reopened.call('prepare_save_at', {...saveArgs(1, 144, encode('obsolete after reopen')), expected_head: source.head_digest}), conflictError);
      await sameDatabase(fixture.name, reinserted);
      const got = (await reopened.call('read', {id})).result;
      if (got.revision !== 1n || !equal(got.payload, encode('new incarnation'))) throw Error('stale queued edit overwrote replacement record');
      reopened.terminate();
      return {...boundary, invalid_source_width_or_type_rejections: 5, owner_and_worker_admission: true, implicit_revision_only_aliases_absent: true, caller_head_copied_before_transport_wait: true, delayed_transport_revision_aba_rejected: true, freshly_reopened_revision_aba_rejected: true, stale_intent_preserved_all_stores: true};
    });
    await record('save_source_head_preserves_unknown_and_exact_latest_retry', async () => {
      const fixture = await fresh('save-source-retry'), source = (await fixture.owner.call('begin_records')).result.receipt;
      const intent = {...saveArgs(1, 145, encode('head-bound replacement')), expected_head: source.head_digest};
      await expectReject(fixture.owner.call('save_at', {...intent, lostAck: true}), uncertainError);
      await expectReject(fixture.owner.call('save_at', intent), uncertainError);
      const reconciled = (await fixture.owner.call('reconcile_latest', {request: request(145)})).result;
      const committed = await snapshotDatabase(fixture.name);
      await expectReject(fixture.owner.call('save_at', intent), conflictError);
      const retry = (await fixture.owner.call('save_at', {...intent, expected_head: receipt(reconciled).head_digest})).result;
      if (!retry.replay || !equalReceipt(reconciled, retry) || Object.values(retry.writes).some(value => value !== 0)) throw Error('head-bound latest save retry wrote data');
      await expectReject(fixture.owner.call('save_at', {...intent, expected_head: receipt(reconciled).head_digest, payload: encode('changed intent')}), /OperationIdReuse|reuse/i);
      await sameDatabase(fixture.name, committed);
      fixture.owner.terminate(); const reopened = await reopen(fixture.name);
      const latest = (await reopened.call('begin_records')).result.receipt;
      await expectReject(reopened.call('save_at', intent), conflictError);
      const again = (await reopened.call('save_at', {...intent, expected_head: latest.head_digest})).result;
      if (!again.replay || !equalReceipt(reconciled, again) || Object.values(again.writes).some(value => value !== 0)) throw Error('reopened latest save retry wrote data');
      await sameDatabase(fixture.name, committed); reopened.terminate();
      return {unknown_blocks_further_use: true, unknown_reconciled_by_operation_id: true, submitted_source_cannot_be_replayed_after_commit: true, changed_content_rejected: true, explicit_current_head_latest_retry_zero_writes: true, reopened_latest_retry_zero_writes: true};
    });
    await record('paged_inventory_streams_verified_bounded_snapshot_and_orders_writer', async () => {
      // Five = two full caller-requested pages plus a partial final page. This
      // tests page boundaries, not a product page/population limit.
      const fixture = await fresh('record-pages', false, 6); await fixture.owner.call('seedFixture', {records: 5});
      const raw = await snapshotDatabase(fixture.name, true), expected = raw.stores.find(value => value.store === 'records').keys;
      const begun = (await fixture.owner.call('begin_records')).result, pages = [], observed = [];
      do {
        const page = (await fixture.owner.call('record_page', {maximum: 2})).result; pages.push(page);
        if (!equalReceipt(begun, page) || page.records.length > 2 || page.stats.retained_page_records !== page.records.length || page.stats.records_checked !== page.records.length || page.stats.max_stack_nodes > 129 || page.stats.max_cached_nodes > 1 || page.stats.max_record_rows > 1 || page.stats.get_all_calls !== 0 || page.stats.transactions !== 1 || page.stats.record_bodies_materialized !== page.records.length || page.stats.arraybuffer_row_clones !== (storageProfile === 'arraybuffer' ? page.records.length : 0)) throw Error('record page proof/retention/snapshot invariant failed');
        for (const member of page.records) {if (member.revision !== 1n) throw Error('inventory rounded/changed revision'); observed.push(hex(member.id));}
      } while (!pages.at(-1).complete);
      if (pages.length !== 3 || pages.slice(0, -1).some(value => value.complete) || pages.at(-1).records.length !== 1 || pages.reduce((total, page) => total + page.stats.nodes_read, 0) !== 9 || JSON.stringify(observed) !== JSON.stringify(expected)) throw Error('paged traversal omitted/duplicated a member or claimed early completion');
      await expectReject(fixture.owner.call('record_page', {maximum: 2}), conflictError);
      const writer = await reopen(fixture.name, 6); await fixture.owner.call('begin_records');
      const paused = fixture.owner.waitProgress('page-snapshot-paused'), reading = fixture.owner.call('record_page', {maximum: 2, pause: 'page-snapshot'}); await paused;
      const queued = writer.waitProgress('publish-transaction-opened');
      let writerSettled = false; const writing = writer.call('save_revision_diagnostic', saveArgs(0, 136, payload)).then(value => {writerSettled = true; return value;}); await queued;
      if (writerSettled) throw Error('writer committed while the page readonly snapshot was held');
      await fixture.owner.call('release', {barrier: 'page-snapshot'}); const captured = (await reading).result; await writing;
      if (captured.complete || captured.records.length !== 2 || !equalReceipt(captured, begun) || captured.records.some(member => hex(member.id) === hex(id))) throw Error('page mixed a concurrent newer commit into its source snapshot');
      await expectReject(fixture.owner.call('record_page', {maximum: 2}), conflictError);
      fixture.owner.terminate(); writer.terminate();
      return {page_size: 2, source_records: 5, source_nodes: 9, page_lengths: pages.map(value => value.records.length), pages: pages.map(value => value.stats), complete_only_after_finality: true, exact_independent_inventory: true, readonly_snapshot_orders_writer: true, changed_head_rejects_next_page: true, no_full_inventory_cache: true};
    });
    await record('paged_inventory_errors_cancel_cursor_and_never_skip_corrupt_members', async () => {
      const fixture = await fresh('record-page-errors', false, 6); await fixture.owner.call('seedFixture', {records: 5});
      const raw = await snapshotDatabase(fixture.name, true), rows = raw.stores.find(value => value.store === 'records'), nodes = raw.stores.find(value => value.store === 'nodes');
      const targetKey = rows.keys[2], targetRow = rows.values[2], targetId = Uint8Array.from(targetKey.match(/../g), value => parseInt(value, 16));
      const targetNode = nodes.values.findIndex(value => {const body = new Uint8Array(value); return body[0] === 0 && equal(body.slice(1, 17), targetId);});
      if (targetNode < 0) throw Error('inventory corruption fixture leaf missing');
      for (const maximum of [0, -1, 1.5, 4294967296, '2', null]) {
        await fixture.owner.call('begin_records'); await expectReject(fixture.owner.call('record_page', {maximum}), /InvalidInput|page size|ResourceLimit/i);
      }
      const prefix = async () => {await fixture.owner.call('begin_records'); const page = (await fixture.owner.call('record_page', {maximum: 2})).result; if (page.complete || page.records.length !== 2) throw Error('corruption fixture prefix was not partial');};
      const rejectsAndCancels = async () => {await expectReject(fixture.owner.call('record_page', {maximum: 2}), integrityError); await expectReject(fixture.owner.call('record_page', {maximum: 2}), conflictError);};
      await prefix();
      const length = targetRow.envelope instanceof Blob ? targetRow.envelope.size : targetRow.envelope.byteLength, corrupted = new Uint8Array(length);
      await editDatabase(fixture.name, tx => tx.objectStore('records').put({...targetRow, envelope: storageProfile === 'blob' ? new Blob([corrupted]) : corrupted.buffer}, targetKey));
      await rejectsAndCancels(); await editDatabase(fixture.name, tx => tx.objectStore('records').put(targetRow, targetKey));
      await prefix(); await editDatabase(fixture.name, tx => tx.objectStore('nodes').delete(nodes.keys[targetNode]));
      await rejectsAndCancels(); await editDatabase(fixture.name, tx => tx.objectStore('nodes').put(nodes.values[targetNode], nodes.keys[targetNode]));
      await prefix(); const orphanRecord = hex(new Uint8Array(16).fill(99));
      await editDatabase(fixture.name, tx => tx.objectStore('records').put(targetRow, orphanRecord));
      await rejectsAndCancels(); await editDatabase(fixture.name, tx => tx.objectStore('records').delete(orphanRecord));
      await prefix(); const orphanNode = hex(new Uint8Array(32).fill(99));
      await editDatabase(fixture.name, tx => tx.objectStore('nodes').put(nodes.values[targetNode], orphanNode));
      await rejectsAndCancels(); await editDatabase(fixture.name, tx => tx.objectStore('nodes').delete(orphanNode));
      await prefix(); await fixture.owner.call('save_revision_diagnostic', {id: targetId, expected: 1n, metadata, payload, request: request(137)});
      await expectReject(fixture.owner.call('record_page', {maximum: 2}), conflictError);
      await fixture.owner.call('begin_records');
      const paused = fixture.owner.waitProgress('page-complete-paused'), reading = fixture.owner.call('record_page', {maximum: 2, pause: 'page-complete'});
      const revoked = expectReject(reading, /stale|locked|revoked/i); await paused; await fixture.owner.call('lock'); await revoked;
      await expectReject(fixture.owner.call('record_page', {maximum: 2}), /locked/i);
      await fixture.owner.call('unlock', {password}); await expectReject(fixture.owner.call('record_page', {maximum: 2}), conflictError);
      await fixture.owner.call('begin_records'); let final; do {final = (await fixture.owner.call('record_page', {maximum: 2})).result;} while (!final.complete);
      fixture.owner.terminate();
      return {page_size: 2, invalid_page_sizes_rejected: 6, ciphertext_corruption_rejected: true, missing_node_rejected: true, orphan_record_rejected: true, orphan_node_rejected: true, error_poisoned_cursor: true, same_session_head_change_rejected: true, lock_after_transaction_revokes_page_publication: true, unlocked_session_cannot_reuse_old_cursor: true, fresh_inventory_completes_after_repairs: true};
    });
    await record('streaming_startup_inventory_is_bounded', async () => {for (const records of [1, 16, 256, 4096]) {const fixture = await fresh('growth-' + records, false, records); await fixture.owner.call('seedFixture', {records}); fixture.owner.terminate(); const measuring = new Owner(); await measuring.call('open', {name: fixture.name, max_records: records}); const response = await measuring.call('unlock', {password}), result = response.result, stats = result.stats; if (!stats) throw Error('streaming startup metrics missing'); const observed = {...stats, records, correctness: true, elapsed_ms: response.elapsed_ms, memory_bytes: result.memory_bytes}; if (observed.nodes_read !== 2 * records - 1 || observed.records_checked !== records || observed.max_stack_nodes > 129 || observed.max_cached_nodes > 1 || observed.max_record_rows > 1 || observed.get_all_calls !== 0 || observed.transactions !== 1 || observed.head_bytes !== 129 || observed.record_bodies_materialized !== (storageProfile === 'arraybuffer' ? records : 0)) throw Error('streaming startup work/retention invariant failed'); growth.push(observed); measuring.terminate();} return {record_populations: growth.map(value => value.records), key_bits: 128, whole_inventory_materialized: false};});

    const estimate = await navigator.storage?.estimate?.();
    const result = {schema: 'fogvault-browser-feasibility/v1', pass: cases.every(value => value.status === 'pass'), cases, samples, growth, environment: {user_agent: navigator.userAgent, hardware_concurrency: navigator.hardwareConcurrency, secure_context: isSecureContext, indexeddb: !!indexedDB, webassembly: !!WebAssembly, worker: true}, storage_estimate: estimate ?? null, scope: {storage_schema_version: 2, storage_profile: storageProfile, storage_admission: storageProfile === 'blob' ? 'Blob size admitted before arrayBuffer materialization' : 'ArrayBuffer clone happens in IDB before JS/WASM length admission; hostile-store total-allocation admission unqualified', payload_fixture_bytes: 16 * 1024 * 1024, metadata_policy_bytes: 32, record_policy: 'explicit per-fixture 1,16,256,4096; independent of production limits', main_thread_payloads: 'structured clone; caller-owned JS plaintext copies remain', wasm_memory: 'linear-memory buffer high-water extent; not live heap or process RSS', unlock_inventory: 'incremental Rust DFS and one record row per callback in one readonly snapshot; no full inventory arrays', point_operations: 'one readonly capture of head, record and at most129 hash-bound nodes, verified outside transaction', transaction_contract: 'atomic CAS writes, definite rollback, latest retry and uncertain latest reconciliation; no receipt history', durability: 'transaction completion with strict hint; no power-cut or eviction guarantee', growth_seed: 'P2 Rust plans staged for a single atomic fixture transaction; seeding memory excluded by fresh Worker before each startup observation', consumer: 'opaque16MiB byte-bound fixture; exact beta3 API integration is verified separately by native profile'}};
    document.querySelector('#result').textContent = JSON.stringify(result, null, 2); window.fogvaultResult = result; return result;
  } catch (error) {const result = {schema: 'fogvault-browser-feasibility/v1', pass: false, cases, samples, growth, error: String(error), environment: {user_agent: navigator.userAgent}}; document.querySelector('#result').textContent = JSON.stringify(result, null, 2); window.fogvaultResult = result; return result;}
  finally {for (const active of [...owners]) active.terminate(); for (const database of databases) indexedDB.deleteDatabase(database);}
})();
