// Disposable P2 browser host. The storage schema is experimental version 2;
// encrypted descriptor/record/head/node bytes keep their existing P2 contract.
import init, {BrowserSession, memory_bytes, revision_roundtrip, validate_kdf_policy} from '../pkg/fogvault_browser_feasibility.js';
import {DATABASE_VERSION, STORES, hex, equal, failure, convertError, header, recordMeta, packRecord, materialize, nodeBytes, openDatabase, transact, currentState, capture} from './idb.mjs';
import {validatePasswordBytes, wipePasswordArguments} from './password.mjs';
await init();
const STORAGE = new URL(import.meta.url).searchParams.get('storage') || 'blob';
if (!['blob', 'arraybuffer'].includes(STORAGE)) throw Error('unsupported-explicit-storage-profile');
// Explicit synthetic fixture inputs; these are not product defaults.
const LIMITS = {payload: 16 * 1024 * 1024, metadata: 32, records: 4096};
let session = null, candidate = null, db = null, epoch = 0, prepared = null, busy = false;
const active = new Set(), barriers = new Map();
let bulkCalls = 0, kdfProfiles;
const writeCalls = {state: 0, records: 0, nodes: 0};
for (const method of ['add', 'put', 'delete', 'clear']) {
  const original = IDBObjectStore.prototype[method];
  IDBObjectStore.prototype[method] = function(...args) {
    if (Object.hasOwn(writeCalls, this.name)) writeCalls[this.name]++;
    return original.apply(this, args);
  };
}
const writesSince = before => Object.fromEntries(Object.keys(writeCalls).map(name => [name, writeCalls[name] - before[name]]));
for (const method of ['getAll', 'getAllKeys']) {
  const original = IDBObjectStore.prototype[method];
  IDBObjectStore.prototype[method] = function(...args) { bulkCalls++; return original.apply(this, args); };
}
const progress = (name, fields = {}) => postMessage({progress: name, ...fields});
function requireDatabase() { if (!db) throw failure('StorageClosed', 'database connection closed'); return db; }
function requireSession(allowUnknown = false) {
  requireDatabase();
  if (!session) throw failure('Locked', 'vault is locked');
  if (!allowUnknown) session.check_available();
  return session;
}
function release(name) { const finish = barriers.get(name); if (finish) { barriers.delete(name); finish(); } }
function revoke() {
  epoch++; prepared = null;
  for (const name of [...barriers.keys()]) release(name);
  for (const transaction of [...active]) { try { transaction.abort(); } catch { /* Already completed. */ } }
  if (candidate) candidate.lock(); // Its owning operation frees it in finally.
  if (session) { session.lock(); session.free(); session = null; }
}
function policy(args) {
  // The allowlist is supplied by the host, never copied from the file header.
  validate_kdf_policy(args.kdf_profiles);
  kdfProfiles = args.kdf_profiles;
  if (args.max_records !== undefined) {
    if (!Number.isSafeInteger(args.max_records) || args.max_records <= 0 || args.max_records > 0xffffffff) throw failure('ResourceLimit', 'invalid explicit fixture record policy');
    LIMITS.records = args.max_records;
  }
}
async function connect(args, create) {
  if (db) { db.close(); db = null; }
  policy(args);
  const opened = await openDatabase(args.name, create, () => { revoke(); db = null; progress('versionchange'); });
  db = opened.database;
  return opened.created;
}
function waitOutside(name, signal = name + '-paused') {
  return new Promise(resolve => { barriers.set(name, resolve); progress(signal); });
}
// Test-only pause: normal streaming never pumps requests or waits for a callback.
function holdTransaction(context, name, continuation) {
  let released = false;
  barriers.set(name, () => { released = true; });
  progress(name + '-paused');
  const pump = () => {
    if (released) { barriers.delete(name); continuation(); return; }
    const query = context.store('state').get('current');
    query.onsuccess = context.guard(pump);
  };
  pump();
}
function input(args) {
  if (!(args.payload instanceof Uint8Array) || args.payload.length > LIMITS.payload || !(args.metadata instanceof Uint8Array) || args.metadata.length > LIMITS.metadata) throw failure('ResourceLimit', 'resource-policy-before-wasm-copy');
  if (!(args.id instanceof Uint8Array) || args.id.length !== 16 || !(args.request instanceof Uint8Array) || args.request.length !== 16) throw failure('Malformed', 'identity-width');
  const value = args.expected === undefined ? 0n : args.expected;
  if (typeof value !== 'bigint' && !(typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)) throw failure('Malformed', 'expected revision must be a BigInt or safe nonnegative integer');
  const expected = BigInt(value);
  if (expected < 0n || expected > 9223372036854775807n) throw failure('Malformed', 'expected revision outside the record revision domain');
  return expected;
}
function deleteInput(args) {
  if (!(args.id instanceof Uint8Array) || args.id.length !== 16 || !(args.request instanceof Uint8Array) || args.request.length !== 16) throw failure('Malformed', 'identity-width');
  const value = args.expected;
  if (typeof value !== 'bigint' && !(typeof value === 'number' && Number.isSafeInteger(value) && value > 0)) throw failure('InvalidInput', 'delete requires positive exact revision');
  const expected = BigInt(value);
  if (expected <= 0n || expected > 9223372036854775807n) throw failure('InvalidInput', 'delete revision range');
  return expected;
}
function synchronousEnvelope(row) {
  if (STORAGE === 'blob') {
    if (typeof FileReaderSync !== 'function') throw failure('UnsupportedCapability', 'Blob record verification requires Worker FileReaderSync');
    return new Uint8Array(new FileReaderSync().readAsArrayBuffer(row.envelope));
  }
  return new Uint8Array(row.envelope);
}
async function prepareDelete(args, strict = false) {
  const expected = deleteInput(args), object = requireSession();
  if (prepared) throw failure('Conflict', 'an operation is already prepared');
  if (strict) {
    if (!(args.expected_head instanceof Uint8Array) || args.expected_head.length !== 32) throw failure('InvalidInput', '32-byte expected head required');
    object.check_expected_head(args.expected_head);
  }
  const start = epoch;
  const captured = await capture(requireDatabase(), STORAGE, LIMITS, args.id, object.descriptor(), object.head(), active, true);
  if (start !== epoch || object !== session) throw failure('StaleSession', 'delete preparation revoked');
  object.check_snapshot(captured.state.descriptor, captured.state.head);
  const old = captured.row ? await materialize(captured.row.envelope) : new Uint8Array();
  if (start !== epoch || object !== session) throw failure('StaleSession', 'delete preparation revoked');
  const plan = strict
    ? object.prepare_delete_at(args.expected_head, args.id, expected, args.request, captured.nodes, old, captured.meta?.revision || 0n)
    : object.prepare_delete(args.id, expected, args.request, captured.nodes, old, captured.meta?.revision || 0n);
  prepared = {deletion: true, plan, id: args.id.slice(), start, object, captured, old};
  return {prepared: true, replay: plan.replay, receipt: plan.receipt, path_nodes: captured.nodes.length, memory_bytes: memory_bytes()};
}
async function recordPage(args) {
  const object = requireSession(), start = epoch, before = bulkCalls;
  let finished, bodyMaterializations = 0;
  const live = () => { if (start !== epoch || object !== session) throw failure('StaleSession', 'page revoked'); };
  try {
    await transact(requireDatabase(), 'readonly', context => {
      const state = context.store('state').get('current');
      state.onsuccess = context.guard(() => {
        live();
        const value = header(state.result, STORAGE); object.check_snapshot(value.descriptor, value.head);
        object.start_record_page(args.maximum);
        const counts = {}; let pending = 2;
        for (const name of ['records', 'nodes']) {
          const request = context.store(name).count();
          request.onsuccess = context.guard(() => {
            live();
            if (!Number.isSafeInteger(request.result) || request.result < 0 || request.result > (name === 'records' ? LIMITS.records : Math.max(0, 2 * LIMITS.records - 1))) throw failure('ResourceLimit', 'page inventory count');
            counts[name] = request.result;
            if (--pending === 0) {
              if (args.pause === 'page-snapshot') holdTransaction(context, 'page-snapshot', next);
              else next();
            }
          });
        }
        const next = () => {
          live();
          const wanted = object.record_page_next();
          if (wanted.kind === 'done') {
            finished = object.finish_record_page(BigInt(counts.records), BigInt(counts.nodes)); context.result(true); return;
          }
          if (wanted.kind === 'node') {
            const request = context.store('nodes').get(hex(wanted.hash));
            request.onsuccess = context.guard(() => { live(); object.supply_record_page_node(nodeBytes(request.result)); next(); }); return;
          }
          if (wanted.kind === 'record') {
            const request = context.store('records').get(hex(wanted.id));
            request.onsuccess = context.guard(() => {
              live();
              const meta = recordMeta(request.result, STORAGE, LIMITS); bodyMaterializations++;
              object.supply_record_page_row(meta.revision, synchronousEnvelope(request.result)); next();
            }); return;
          }
          throw failure('Integrity', 'unknown page request');
        };
      });
    }, active);
    if (args.pause === 'page-complete') await waitOutside('page-complete');
    if (start !== epoch || object !== session) throw failure('StaleSession', 'page publication revoked');
    return {...finished, stats: {...finished.stats, transactions: 1, get_all_calls: bulkCalls - before, max_cached_nodes: finished.stats.nodes_read ? 1 : 0,
      max_record_rows: finished.records.length ? 1 : 0, retained_page_records: finished.records.length, record_bodies_materialized: bodyMaterializations,
      arraybuffer_row_clones: STORAGE === 'arraybuffer' ? bodyMaterializations : 0}, memory_bytes: memory_bytes()};
  } catch (error) {
    if (start === epoch && object === session) object.cancel_records();
    throw error;
  }
}
async function auditSnapshot(object, start, options = {}) {
  const database = requireDatabase(), getAllBefore = bulkCalls;
  const counts = {records: 0, nodes: 0};
  let finished, bodyClones = 0;
  try { await transact(database, 'readonly', context => {
    const state = context.store('state').get('current');
    state.onsuccess = context.guard(() => {
      const value = header(state.result, STORAGE);
      if (options.reconcile) object.begin_reconcile_snapshot(value.descriptor, value.head, options.request);
      else {
        if (!equal(value.descriptor, object.descriptor())) throw failure('Conflict', 'descriptor changed during key derivation');
        object.begin_audit(value.head);
      }
      let countPending = 2;
      for (const name of ['records', 'nodes']) {
        const count = context.store(name).count();
        count.onsuccess = context.guard(() => {
          if (!Number.isSafeInteger(count.result) || count.result < 0) throw failure('ResourceLimit', 'inventory count range');
          counts[name] = count.result;
          if (--countPending === 0) {
            if (counts.records > LIMITS.records || counts.nodes > Math.max(0, 2 * LIMITS.records - 1)) throw failure('ResourceLimit', 'inventory count exceeds explicit fixture policy');
            if (options.pause === 'startup') holdTransaction(context, 'startup', next);
            else next();
          }
        });
      }
      const next = () => {
        if (start !== epoch) throw failure('StaleSession', 'stale-unlock');
        const wanted = object.audit_next();
        if (wanted.kind === 'done') {
          finished = object.finish_audit(BigInt(counts.records), BigInt(counts.nodes));
          context.result(true); return;
        }
        if (wanted.kind === 'node') {
          const node = context.store('nodes').get(hex(wanted.hash));
          node.onsuccess = context.guard(() => { object.supply_node(nodeBytes(node.result)); next(); });
          return;
        }
        if (wanted.kind === 'record') {
          const row = context.store('records').get(hex(wanted.id));
          row.onsuccess = context.guard(() => {
            const meta = recordMeta(row.result, STORAGE, LIMITS);
            if (STORAGE === 'arraybuffer') bodyClones++;
            object.supply_record(meta.revision, BigInt(meta.length)); next();
          });
          return;
        }
        throw failure('Integrity', 'unknown stream request');
      };
    });
  }, active); } catch (error) {
    if (start === epoch) object.abort_audit(); // Keep an uncertain receipt pending; discard only its incomplete cursor.
    throw error;
  }
  if (start !== epoch) throw failure('StaleSession', 'stale-unlock');
  const receipt = object.activate_audit();
  return {receipt, stats: {
    records: counts.records, nodes_read: finished.nodes_read, records_checked: finished.records_checked,
    node_bytes: finished.node_bytes, max_stack_nodes: finished.peak_buffered_nodes,
    max_cached_nodes: counts.nodes ? 1 : 0, max_record_rows: counts.records ? 1 : 0,
    get_all_calls: bulkCalls - getAllBefore, transactions: 1, header_transactions: options.reconcile ? 0 : 1,
    head_bytes: 129, record_bodies_materialized: bodyClones, memory_bytes: memory_bytes(),
    snapshot: 'one readonly transaction; application retains one node/record result at a time'
  }};
}
async function prepare(args, strict = false) {
  const expected = input(args);
  const object = requireSession();
  if (prepared) throw failure('Conflict', 'an operation is already prepared');
  if (strict) {
    if (!(args.expected_head instanceof Uint8Array) || args.expected_head.length !== 32) throw failure('InvalidInput', '32-byte expected head required');
    // Admit caller intent before storage/body materialization or WASM copies.
    object.check_expected_head(args.expected_head);
  }
  const start = epoch;
  const captured = await capture(requireDatabase(), STORAGE, LIMITS, args.id, object.descriptor(), object.head(), active);
  if (start !== epoch || object !== session) throw failure('StaleSession', 'stale-epoch');
  object.check_snapshot(captured.state.descriptor, captured.state.head);
  const old = captured.row ? await materialize(captured.row.envelope) : new Uint8Array();
  if (start !== epoch || object !== session) throw failure('StaleSession', 'stale-epoch');
  const plan = strict
    ? object.prepare_save_at(args.expected_head, args.id, expected, args.metadata, args.payload, args.request, captured.nodes, old, captured.meta?.revision || 0n)
    : object.prepare_save_revision_diagnostic(args.id, expected, args.metadata, args.payload, args.request, captured.nodes, old, captured.meta?.revision || 0n);
  prepared = {plan, id: args.id.slice(), start, object, captured, old};
  return {prepared: true, replay: plan.replay, receipt: plan.receipt, key_effect: plan.key_effect, memory_bytes: memory_bytes(), path_nodes: captured.nodes.length};
}
async function prepareCredential(args, kind) {
  const object = requireSession();
  if (prepared) throw failure('Conflict', 'an operation is already prepared');
  if (!(args.request instanceof Uint8Array) || args.request.length !== 16) throw failure('Malformed', 'request identity width');
  if (!(args.password instanceof Uint8Array) || (kind === 'password' && !(args.new_password instanceof Uint8Array))) throw failure('Malformed', 'password bytes required');
  const start = epoch;
  const state = await currentState(requireDatabase(), STORAGE, active);
  if (start !== epoch || object !== session) throw failure('StaleSession', 'credential preparation revoked');
  object.check_snapshot(state.descriptor, state.head);
  // Both password derivation and root rewrapping complete before a write TX.
  progress('credential-kdf-started');
  const plan = kind === 'password'
    ? object.prepare_password_change(args.password, args.new_password, args.request)
    : object.prepare_kdf_upgrade(args.password, args.target, args.request);
  progress('credential-kdf-finished');
  prepared = {credential: true, plan, start, object};
  return {prepared: true, replay: plan.replay, receipt: plan.receipt, memory_bytes: memory_bytes()};
}
async function publishCredential(options = {}) {
  if (!prepared?.credential || !session || prepared.start !== epoch) throw failure('StaleSession', 'stale credential preparation');
  const current = prepared;
  if (options.pause === 'precommit') await waitOutside('precommit');
  if (current.start !== epoch || session !== current.object || prepared !== current) throw failure('StaleSession', 'credential publication revoked');
  prepared = null;
  const writesBefore = {...writeCalls};
  if (current.plan.replay) {
    const fresh = await currentState(requireDatabase(), STORAGE, active);
    if (current.start !== epoch || session !== current.object) throw failure('StaleSession', 'credential replay revoked');
    current.object.check_snapshot(fresh.descriptor, fresh.head);
    if (!equal(fresh.descriptor, current.plan.descriptor) || !equal(fresh.head, current.plan.head)) throw failure('Conflict', 'latest credential receipt changed');
    return {saved: true, credential_changed: true, key_effect: current.plan.key_effect, replay: true, receipt: current.plan.receipt, writes: writesSince(writesBefore), memory_bytes: memory_bytes()};
  }
  let completed = false;
  try {
    await transact(requireDatabase(), 'readwrite', context => {
      progress('credential-publish-transaction-opened');
      const query = context.store('state').get('current');
      query.onsuccess = context.guard(() => {
        const state = header(query.result, STORAGE);
        if (current.start !== epoch || !equal(state.descriptor, current.plan.prior_descriptor) || !equal(state.head, current.plan.prior_head)) throw failure('Conflict', 'credential descriptor/head conflict');
        context.store('state').put({...state, descriptor: current.plan.descriptor, head: current.plan.head}, 'current');
        if (options.fault === 'clone') context.store('state').put(() => {}, 'synthetic-invalid-clone');
        if (options.fault === 'quota') throw new DOMException('synthetic quota rejection after queued credential write', 'QuotaExceededError');
        if (options.abort) throw failure('NotCommitted', 'injected credential abort');
        context.result(true);
      });
    }, active);
    completed = true;
    if (options.pause === 'postcommit') await waitOutside('postcommit');
    if (current.start !== epoch || session !== current.object) throw failure('OutcomeUnknown', 'revoked credential outcome requires reopen');
    if (options.lostAck) {
      current.object.mark_unknown();
      const error = failure('OutcomeUnknown', 'credential outcome requires reconciliation'); error.request_id = current.plan.receipt.request_id; throw error;
    }
    if (options.fault === 'confirm') throw failure('InjectedFailure', 'synthetic confirmation failure after credential transaction completion');
    const receipt = current.object.confirm_credential(current.plan.descriptor, current.plan.head);
    return {saved: true, credential_changed: true, key_effect: current.plan.key_effect, replay: false, receipt, writes: writesSince(writesBefore), memory_bytes: memory_bytes()};
  } catch (error) {
    if (completed) {
      // I/O already completed. Never turn a later confirmation/serialization
      // failure into a known abort or strand a prepared operation unreconcilable.
      if (current.start === epoch && current.object === session) {
        try { current.object.mark_unknown(); }
        catch { revoke(); } // Acceptance may already have won; reopen is safe.
      }
      const unknown = failure('OutcomeUnknown', 'credential commit completed; reconcile the latest receipt or reopen');
      unknown.request_id = current.plan.receipt.request_id;
      throw unknown;
    }
    if (current.start === epoch && current.object === session) current.object.abort();
    throw error;
  }
}

async function publish(options = {}) {
  if (prepared?.credential) return publishCredential(options);
  if (!prepared || !session || prepared.start !== epoch) throw failure('StaleSession', 'stale-prepared-operation');
  const current = prepared;
  if (options.pause === 'precommit') await waitOutside('precommit');
  if (current.start !== epoch || session !== current.object || prepared !== current) throw failure('StaleSession', 'stale-prepared-operation');
  prepared = null;
  const writesBefore = {...writeCalls};
  if (current.plan.replay) {
    const fresh = await capture(requireDatabase(), STORAGE, LIMITS, current.id, current.object.descriptor(), current.plan.head, active);
    if (current.start !== epoch || session !== current.object) throw failure('StaleSession', 'replay revoked');
    current.object.check_snapshot(fresh.state.descriptor, fresh.state.head);
    const envelope = fresh.row ? await materialize(fresh.row.envelope) : new Uint8Array();
    if (current.start !== epoch || session !== current.object) throw failure('StaleSession', 'replay revoked');
    if (current.deletion) {
      if (fresh.row) throw failure('Integrity', 'deleted record reappeared without committed membership');
      current.object.verify_absent(current.id, fresh.nodes);
    } else current.object.verify_record(current.id, fresh.nodes, envelope, fresh.meta?.revision || 0n);
    return {saved: true, deleted: !!current.deletion, replay: true, receipt: current.plan.receipt, writes: writesSince(writesBefore), memory_bytes: memory_bytes()};
  }
  let completed = false;
  try {
    await transact(requireDatabase(), 'readwrite', context => {
      progress('publish-transaction-opened');
      const query = context.store('state').get('current');
      query.onsuccess = context.guard(() => {
        const state = header(query.result, STORAGE);
        if (current.start !== epoch || !equal(state.descriptor, current.captured.state.descriptor) || !equal(state.head, current.plan.prior_head)) throw failure('Conflict', 'accepted-head-conflict');
        let pending = 0;
        const presentNew = new Set();
        const check = (store, key, callback) => {
          pending++; const request = context.store(store).get(key);
          request.onsuccess = context.guard(() => { callback(request.result); if (--pending === 0) write(); });
        };
        const write = () => {
          if (current.start !== epoch) throw failure('StaleSession', 'publication revoked');
          if (current.deletion) context.store('records').delete(hex(current.id));
          else context.store('records').put({revision: current.plan.revision, envelope: packRecord(current.plan.envelope, STORAGE)}, hex(current.id));
          for (const [hash, body] of current.plan.nodes) if (!presentNew.has(hex(hash))) context.store('nodes').add(body.slice().buffer, hex(hash));
          for (const hash of current.plan.obsolete) context.store('nodes').delete(hex(hash));
          context.store('state').put({...state, head: current.plan.head}, 'current');
          if (options.fault === 'clone') context.store('state').put(() => {}, 'synthetic-invalid-clone');
          if (options.fault === 'quota') throw new DOMException('synthetic quota rejection after queued writes', 'QuotaExceededError');
          if (options.abort) throw failure('NotCommitted', 'injected-abort');
          context.result(true);
        };
        check('records', hex(current.id), row => {
          if (current.captured.row) {
            const meta = recordMeta(row, STORAGE, LIMITS);
            if (meta.revision !== current.captured.meta.revision || meta.length !== current.captured.meta.length) throw failure('Integrity', 'selected record changed without a committed head');
            let actual;
            if (STORAGE === 'blob') {
              if (typeof FileReaderSync !== 'function') throw failure('UnsupportedCapability', 'Blob publication requires Worker FileReaderSync');
              actual = new Uint8Array(new FileReaderSync().readAsArrayBuffer(row.envelope));
            } else actual = new Uint8Array(row.envelope);
            if (!equal(actual, current.old)) throw failure('Integrity', 'selected ciphertext changed without a committed head');
          } else if (row !== undefined) throw failure('Integrity', 'uncommitted extra row cannot be overwritten');
        });
        for (const [hash, bytes] of current.captured.nodes) check('nodes', hex(hash), value => {
          if (!equal(nodeBytes(value), bytes)) throw failure('Integrity', 'captured immutable node changed');
        });
        for (const [hash, body] of current.plan.nodes) check('nodes', hex(hash), value => {
          if (value !== undefined) { if (!equal(nodeBytes(value), body)) throw failure('Integrity', 'immutable node collision or corruption'); presentNew.add(hex(hash)); }
        });
      });
    }, active);
    completed = true;
    if (options.pause === 'postcommit') await waitOutside('postcommit');
    if (current.start !== epoch || session !== current.object) throw failure('OutcomeUnknown', 'revoked-publication-outcome-requires-reopen');
    if (options.lostAck) {
      current.object.mark_unknown();
      const error = failure('OutcomeUnknown', 'commit outcome requires reconciliation'); error.request_id = current.plan.receipt.request_id; throw error;
    }
    if (options.fault === 'confirm') throw failure('InjectedFailure', 'synthetic confirmation failure after record transaction completion');
    const receipt = current.object.confirm(current.plan.head);
    return {saved: true, deleted: !!current.deletion, replay: false, receipt, writes: writesSince(writesBefore), memory_bytes: memory_bytes()};
  } catch (error) {
    if (completed) {
      if (current.start === epoch && current.object === session) {
        try { current.object.mark_unknown(); } catch { revoke(); }
      }
      const unknown = failure('OutcomeUnknown', 'record commit completed; reconcile or reopen');
      unknown.request_id = current.plan.receipt.request_id; throw unknown;
    }
    if (!completed && current.start === epoch && current.object === session) current.object.abort();
    throw error;
  }
}
async function seedFixture(args) {
  const object = requireSession();
  const records = args.records;
  if (!Number.isSafeInteger(records) || records <= 0 || records > LIMITS.records || object.head()[64] !== 0) throw failure('ResourceLimit', 'seed requires an empty fixture within its declared policy');
  const start = epoch, initialHead = object.head(), nodes = new Map(), rows = new Map();
  // This explicit fixture builder retains its encrypted staging inventory. It is
  // excluded from startup measurements; growth reopens in a fresh Worker.
  try {
    for (let number = 0; number < records; number++) {
      const counter = new Uint8Array(8); new DataView(counter.buffer).setBigUint64(0, BigInt(number));
      const identity = new Uint8Array(await crypto.subtle.digest('SHA-256', counter)).slice(0, 16);
      if (start !== epoch || object !== session) throw failure('StaleSession', 'seed revoked');
      const path = []; let hash = object.head()[64] ? object.head().slice(65, 97) : null;
      while (hash) {
        if (path.length >= 129) throw failure('Integrity', 'fixture path bound');
        const body = nodes.get(hex(hash)); if (!body) throw failure('Integrity', 'fixture node missing');
        path.push([hash, body]);
        if (body[0] === 0) break;
        const split = body[1]; let mismatch = false;
        for (let bit = 0; bit < split; bit++) if ((identity[bit >> 3] ^ body[2 + (bit >> 3)]) & (0x80 >> (bit & 7))) { mismatch = true; break; }
        if (mismatch) break;
        const right = !!(identity[split >> 3] & (0x80 >> (split & 7))); hash = body.slice(right ? 50 : 18, right ? 82 : 50);
      }
      const request = new Uint8Array(16); request.set(counter, 8); request[0] = 0x53;
      const payload = new Uint8Array(32); payload.set(counter);
      const plan = object.prepare_save_revision_diagnostic(identity, 0n, new Uint8Array(), payload, request, path, new Uint8Array(), 0n);
      for (const [key, body] of plan.nodes) nodes.set(hex(key), body);
      for (const key of plan.obsolete) nodes.delete(hex(key));
      rows.set(hex(identity), {revision: plan.revision, envelope: packRecord(plan.envelope, STORAGE)});
      // Fixture-only staging authority: no caller receives these receipts. On any
      // failure the entire object is revoked, rather than pretending rollback.
      object.confirm(plan.head);
    }
    await transact(requireDatabase(), 'readwrite', context => {
      const query = context.store('state').get('current');
      query.onsuccess = context.guard(() => {
        const state = header(query.result, STORAGE);
        if (start !== epoch || !equal(state.head, initialHead)) throw failure('Conflict', 'fixture head changed');
        for (const [key, body] of nodes) context.store('nodes').add(body.slice().buffer, key);
        for (const [key, row] of rows) context.store('records').add(row, key);
        context.store('state').put({...state, head: object.head()}, 'current');
      });
    }, active);
    if (start !== epoch || object !== session) throw failure('OutcomeUnknown', 'fixture publication revoked');
    return {seeded: records, live_nodes: nodes.size, fixture_only: true, memory_bytes: memory_bytes()};
  } catch (error) { revoke(); throw error; }
}
const operations = {
  async create(args) {
    revoke(); const start = epoch;
    const created = await connect(args, true);
    if (start !== epoch) throw failure('StaleSession', 'stale-create');
    // Even an incomplete schema-2 initialization remains an occupied destination.
    if (!created) { db.close(); db = null; throw failure('Exists', 'destination already exists'); }
    if (start !== epoch) throw failure('StaleSession', 'stale-create');
    progress('kdf-started');
    const object = BrowserSession.create_with_kdf_policy(args.password, LIMITS.payload, LIMITS.metadata, LIMITS.records, kdfProfiles); candidate = object;
    progress('kdf-finished');
    try {
      const state = {storage_version: DATABASE_VERSION, node_storage: 'arraybuffer', storage_profile: STORAGE, descriptor: object.descriptor(), head: object.head()};
      await transact(requireDatabase(), 'readwrite', context => { context.store('state').add(state, 'current'); }, active);
      if (start !== epoch) throw failure('OutcomeUnknown', 'revoked-create-outcome-requires-reopen');
      object.confirm_create();
      candidate = null; session = object;
      return {created: true, receipt: object.current_receipt(), memory_bytes: memory_bytes()};
    } finally { if (session !== object) { object.lock(); object.free(); } if (candidate === object) candidate = null; }
  },
  async open(args) {
    revoke(); const start = epoch;
    try {
      await connect(args, false);
      const state = await currentState(requireDatabase(), STORAGE, active);
      if (start !== epoch) throw failure('StaleSession', 'open revoked');
      return {opened: true, head: state.head, memory_bytes: memory_bytes()};
    } catch (error) { db?.close(); db = null; throw error; }
  },
  async unlock(args) {
    revoke(); const start = epoch;
    const state = await currentState(requireDatabase(), STORAGE, active);
    if (args.barrier) await waitOutside('unlock', 'unlock-snapshot-waiting');
    if (start !== epoch) throw failure('StaleSession', 'stale-unlock');
    progress('kdf-started');
    const object = BrowserSession.begin_unlock_with_kdf_policy(state.descriptor, args.password, LIMITS.payload, LIMITS.metadata, LIMITS.records, args.kdf_profiles === undefined ? kdfProfiles : args.kdf_profiles); candidate = object;
    progress('kdf-finished');
    try {
      const result = await auditSnapshot(object, start, args);
      if (start !== epoch) throw failure('StaleSession', 'stale-unlock');
      candidate = null; session = object;
      return {unlocked: true, ...result, memory_bytes: memory_bytes()};
    } finally { if (session !== object) { object.lock(); object.free(); } if (candidate === object) candidate = null; }
  },
  async lock() { revoke(); return {locked: true, memory_bytes: memory_bytes()}; },
  async release(args) { release(args.barrier); return {released: true}; },
  async save_at(args) { await prepare(args, true); return publish(args); },
  async prepare_save_at(args) { return prepare(args, true); },
  // Revision-only operations are explicitly isolated diagnostic entry points.
  async save_revision_diagnostic(args) { await prepare(args); return publish(args); },
  async delete(args) { await prepareDelete(args); return publish(args); },
  async prepare_delete(args) { return prepareDelete(args); },
  async delete_at(args) { await prepareDelete(args, true); return publish(args); },
  async prepare_delete_at(args) { return prepareDelete(args, true); },
  async begin_records() {
    const object = requireSession(), start = epoch;
    const state = await currentState(requireDatabase(), STORAGE, active);
    if (start !== epoch || object !== session) throw failure('StaleSession', 'scan creation revoked');
    object.check_snapshot(state.descriptor, state.head); object.begin_records();
    return {cursor: true, receipt: object.current_receipt()};
  },
  async record_page(args) { return recordPage(args); },
  async cancel_records() { requireSession().cancel_records(); return {cancelled: true}; },
  async change_password(args) { await prepareCredential(args, 'password'); return publish(args); },
  async upgrade_kdf(args) { await prepareCredential(args, 'kdf'); return publish(args); },
  async prepare_password_change(args) { return prepareCredential(args, 'password'); },
  async prepare_kdf_upgrade(args) { return prepareCredential(args, 'kdf'); },
  async prepare_revision_diagnostic(args) { return prepare(args); },
  async publish(args) { return publish(args); },
  async reconcile_latest(args) {
    const object = requireSession(true), start = epoch;
    if (!(args.request instanceof Uint8Array) || args.request.length !== 16) throw failure('Malformed', 'request identity width');
    const result = await auditSnapshot(object, start, {reconcile: true, request: args.request, pause: args.pause});
    if (start !== epoch || object !== session) throw failure('StaleSession', 'reconciliation revoked');
    prepared = null;
    return {...result, reconciled: true, memory_bytes: memory_bytes()};
  },
  async read(args) {
    const object = requireSession(), start = epoch;
    if (!(args.id instanceof Uint8Array) || args.id.length !== 16) throw failure('Malformed', 'identity width');
    const captured = await capture(requireDatabase(), STORAGE, LIMITS, args.id, object.descriptor(), object.head(), active);
    if (args.pause === 'read-captured') await waitOutside('read-captured');
    if (start !== epoch || object !== session) throw failure('StaleSession', 'stale-epoch');
    object.check_snapshot(captured.state.descriptor, captured.state.head);
    const envelope = captured.row ? await materialize(captured.row.envelope) : new Uint8Array();
    if (start !== epoch || object !== session) throw failure('StaleSession', 'stale-epoch');
    const value = object.read(args.id, captured.nodes, envelope);
    if (!captured.meta || value.revision !== captured.meta.revision) throw failure('Integrity', 'row-revision-integrity');
    return {...value, path_nodes: captured.nodes.length, transactions: 1, memory_bytes: memory_bytes()};
  },
  async seedFixture(args) { return seedFixture(args); },
  async tamper(args) {
    await transact(requireDatabase(), 'readwrite', context => { const query = context.store('records').get(hex(args.id)); query.onsuccess = context.guard(() => { const row = query.result; const meta = recordMeta(row, STORAGE, LIMITS); context.store('records').put({...row, envelope: packRecord(new Uint8Array(meta.length), STORAGE)}, hex(args.id)); }); }, active);
    return {tampered: true};
  },
  async integerCrossings() {
    const values = [9007199254740993n, 9223372036854775807n];
    for (const value of values) if (revision_roundtrip(value) !== value) throw Error('u64 crossing rounded');
    let rejected = false; try { revision_roundtrip(9007199254740992); } catch { rejected = true; }
    if (!rejected) throw Error('unsafe Number accepted');
    const object = requireSession();
    for (const invalid of [-1n, 9223372036854775808n, 18446744073709551618n, '2']) {
      let invalidInput = false;
      try { object.prepare_save_revision_diagnostic(new Uint8Array(16), invalid, new Uint8Array(), new Uint8Array(), new Uint8Array(16), [], new Uint8Array(), 0n); }
      catch (error) { if (error?.code !== 'InvalidInput') throw error; invalidInput = true; }
      if (!invalidInput) throw Error('out-of-range direct binding revision accepted');
    }
    return {values: values.map(String), number_input_rejected: true, direct_binding_range_rejection: true, out_of_range_revision_inputs_rejected: true};
  },
  async saveHeadBoundaryChecks() {
    const object = requireSession();
    const invalid = [undefined, null, '0'.repeat(32), Array(32).fill(0), new Uint16Array(32), new Uint8Array(31), new Uint8Array(33)];
    for (const head of invalid) {
      let rejected = false;
      try { object.prepare_save_at(head, new Uint8Array(16), 0n, new Uint8Array(), new Uint8Array(), new Uint8Array(16), [], new Uint8Array(), 0n); }
      catch (error) { if (!['InvalidInput', 'ResourceLimit'].includes(error?.code)) throw error; rejected = true; }
      if (!rejected) throw Error('malformed direct source head was accepted');
    }
    object.check_available();
    return {direct_binding_invalid_source_head_rejections: invalid.length, direct_binding_did_not_prepare_mutation: true};
  },
  async passwordBoundaryChecks() {
    // Fixture-only direct WASM boundary exercise, analogous to integerCrossings.
    // No passwords/keys are returned and successful malformed input is failure.
    const object = requireSession(), descriptor = object.descriptor(), request = new Uint8Array(16);
    const valid = new Uint8Array([97]), invalid = [null, undefined, 1, 'password', [1, 2], {length: 2, 0: 1, 1: 2}, new Uint16Array([1]), new DataView(new ArrayBuffer(1))];
    const detached = new Uint8Array([65]); structuredClone(detached.buffer, {transfer: [detached.buffer]}); invalid.push(detached);
    const sharedAvailable = typeof SharedArrayBuffer === 'function';
    const shared = sharedAvailable ? new Uint8Array(new SharedArrayBuffer(3)) : null;
    if (shared) shared.set([1, 2, 3]);
    let rejections = 0, sharedRejections = 0;
    for (const value of shared ? [...invalid, shared] : invalid) {
      for (const call of [
        () => BrowserSession.create(value, LIMITS.payload, LIMITS.metadata, LIMITS.records),
        () => BrowserSession.create_with_kdf_policy(value, LIMITS.payload, LIMITS.metadata, LIMITS.records, undefined),
        () => BrowserSession.begin_unlock(descriptor, value, LIMITS.payload, LIMITS.metadata, LIMITS.records),
        () => BrowserSession.begin_unlock_with_kdf_policy(descriptor, value, LIMITS.payload, LIMITS.metadata, LIMITS.records, undefined),
        () => object.prepare_password_change(value, valid, request),
        () => object.prepare_password_change(valid, value, request),
        () => object.prepare_kdf_upgrade(value, {memory_kib: 65536, passes: 4}, request),
      ]) {
        let rejected = false;
        try { const result = call(); if (result instanceof BrowserSession) { result.lock(); result.free(); } }
        catch (error) { if (error?.code !== 'InvalidInput') throw error; rejected = true; if (shared && value === shared) sharedRejections++; else rejections++; }
        if (!rejected) throw Error('malformed direct password input was accepted');
      }
    }
    if (shared && !equal(shared, new Uint8Array([1, 2, 3]))) throw Error('direct boundary changed caller-owned shared input');
    object.check_available();
    return {direct_binding_rejections: rejections, invalid_input_errors: true, detached_binding_rejected: true, shared_array_buffer_available: sharedAvailable, shared_binding_rejections: sharedRejections, shared_binding_rejection_executed: sharedAvailable};
  },
  async inspect() {
    const result = await transact(requireDatabase(), 'readonly', context => {
      const value = {}; context.result(value);
      const query = context.store('state').get('current'); query.onsuccess = context.guard(() => { value.head = header(query.result, STORAGE).head; });
      for (const name of ['records', 'nodes']) { const count = context.store(name).count(); count.onsuccess = context.guard(() => { value[name] = count.result; }); }
    }, active);
    return {...result, storage_profile: STORAGE, storage_version: DATABASE_VERSION, memory_bytes: memory_bytes()};
  },
  async close() { revoke(); db?.close(); db = null; return {closed: true}; }
};
self.onmessage = async event => {
  const {requestId, action, args = {}} = event.data;
  const started = performance.now(), control = action === 'lock' || action === 'release';
  let admitted = false;
  try {
    if (!operations[action]) throw failure('Malformed', 'unknown-operation');
    // Reject coercion before revoking a session, creating a database or deriving
    // a key. Structured-cloned credential arrays belong to this Worker.
    validatePasswordBytes(action, args);
    if (!control && busy) throw failure('Conflict', 'worker-busy');
    if (!control) { busy = true; admitted = true; }
    const result = await operations[action](args);
    postMessage({requestId, ok: true, result, elapsed_ms: performance.now() - started});
  } catch (caught) {
    const error = caught?.code ? caught : convertError(caught);
    postMessage({requestId, ok: false, error: String(error), code: error.code, request_id: error.request_id, elapsed_ms: performance.now() - started});
  } finally { wipePasswordArguments(action, args); if (admitted) busy = false; }
};
postMessage({ready: true, memory_bytes: memory_bytes()});
