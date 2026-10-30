// Disposable IndexedDB adapter. Request callbacks keep one transaction snapshot;
// Encryption and ordinary awaits stay outside write TXs. A bounded synchronous
// FileReaderSync comparison validates a Blob predecessor inside its write callback.
export const DATABASE_VERSION = 2;
export const STORES = ['state', 'records', 'nodes'];
export const hex = value => [...value].map(n => n.toString(16).padStart(2, '0')).join('');
export const unhex = value => {
  if (typeof value !== 'string' || !/^[0-9a-f]+$/.test(value) || value.length % 2) throw failure('Integrity', 'invalid stored key');
  return Uint8Array.from(value.match(/../g), n => parseInt(n, 16));
};
export const equal = (a, b) => a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((n, i) => n === b[i]);
export function failure(code, message = code) { const error = new Error(message); error.code = code; return error; }
export function convertError(error) {
  if (error?.code && typeof error.code === 'string') return error;
  const name = error?.name;
  if (name === 'QuotaExceededError') return failure('Capacity', 'storage capacity rejected publication');
  if (name === 'VersionError') return failure('UnsupportedSchema', 'database version is newer than this explicit browser schema');
  if (name === 'InvalidStateError') return failure('StorageClosed', 'storage connection or transaction is closed');
  if (name === 'DataCloneError') return failure('Storage', 'storage value could not be cloned');
  if (name === 'ConstraintError') return failure('Exists', 'destination already exists');
  if (name === 'AbortError') return failure('NotCommitted', 'transaction aborted before publication');
  return failure('Storage', String(error?.message || error));
}
export function header(state, storage) {
  if (!state) throw failure('Integrity', 'missing-state');
  if (state.storage_version !== DATABASE_VERSION || state.node_storage !== 'arraybuffer' || state.storage_profile !== storage) throw failure('UnsupportedSchema', 'unsupported explicit browser storage schema/profile');
  if (state.descriptor instanceof Uint8Array) {
    const magic = String.fromCharCode(...state.descriptor.slice(0, 8));
    if (magic === 'FGVP0001' || magic === 'FGVP0002' || (magic === 'FGVP0003' && state.descriptor.length >= 14 && state.descriptor[12] === 0 && state.descriptor[13] === 2)) throw failure('UnsupportedCapability', 'legacy vault format requires explicit import');
  }
  if (!(state.descriptor instanceof Uint8Array) || state.descriptor.length !== 180 || !(state.head instanceof Uint8Array) || state.head.length !== 129) throw failure('Integrity', 'descriptor-head-admission');
  return state;
}
export const storedSize = value => value instanceof Blob ? value.size : value instanceof ArrayBuffer ? value.byteLength : NaN;
export function recordMeta(row, storage, limits) {
  if (!row || typeof row.revision !== 'bigint' || row.revision <= 0n || row.revision > 9223372036854775807n) throw failure('Integrity', 'missing or invalid committed row');
  if (!(storage === 'blob' ? row.envelope instanceof Blob : row.envelope instanceof ArrayBuffer)) throw failure('Integrity', 'record storage profile mismatch');
  const length = storedSize(row.envelope);
  if (length < 176 || length > limits.payload + limits.metadata + 176) throw failure('ResourceLimit', 'record-admission');
  return {revision: row.revision, length};
}
export const packRecord = (value, storage) => storage === 'blob' ? new Blob([value]) : value.slice().buffer;
export const materialize = async value => new Uint8Array(value instanceof Blob ? await value.arrayBuffer() : value);
export function nodeBytes(value) {
  if (!(value instanceof ArrayBuffer) || (value.byteLength !== 57 && value.byteLength !== 82)) throw failure('Integrity', 'missing or invalid index node');
  return new Uint8Array(value);
}
export function openDatabase(name, create, onVersionChange) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, DATABASE_VERSION);
    let problem = null, created = false;
    request.onupgradeneeded = event => {
      if (!create || event.oldVersion !== 0) {
        problem = failure(event.oldVersion === 0 ? 'NotFound' : 'UnsupportedSchema', event.oldVersion === 0 ? 'existing database not found' : 'legacy browser schema requires explicit migration');
        request.transaction.abort();
        return;
      }
      created = true;
      for (const store of STORES) request.result.createObjectStore(store);
    };
    request.onblocked = () => { problem = failure('StorageBlocked', 'database open blocked by another connection'); reject(problem); };
    request.onerror = () => reject(problem || convertError(request.error));
    request.onsuccess = () => {
      const database = request.result;
      if (problem) { database.close(); reject(problem); return; }
      if (database.version !== DATABASE_VERSION || STORES.some(name => !database.objectStoreNames.contains(name)) || database.objectStoreNames.length !== STORES.length) {
        database.close(); reject(failure('UnsupportedSchema', 'unexpected browser database stores')); return;
      }
      database.onversionchange = () => { onVersionChange?.(); database.close(); };
      resolve({database, created});
    };
  });
}
export function transact(database, mode, setup, active, options = {}) {
  return new Promise((resolve, reject) => {
    let transaction;
    try { transaction = database.transaction(STORES, mode, mode === 'readwrite' ? {durability: 'strict'} : undefined); }
    catch (error) { reject(convertError(error)); return; }
    active?.add(transaction);
    let value, problem = null;
    const fail = error => {
      if (!problem) problem = convertError(error);
      try { transaction.abort(); } catch { /* Completion wins; caller also fences its epoch. */ }
    };
    const guard = callback => event => { try { callback(event); } catch (error) { fail(error); } };
    transaction.oncomplete = () => { active?.delete(transaction); if (problem) reject(problem); else resolve(value); };
    transaction.onabort = () => { active?.delete(transaction); reject(problem || convertError(transaction.error || new DOMException('transaction aborted', 'AbortError'))); };
    transaction.onerror = () => {}; // IndexedDB's default abort remains enabled.
    const context = {transaction, store: name => transaction.objectStore(name), guard, fail, result: result => { value = result; }};
    options.opened?.(transaction);
    try { setup(context); } catch (error) { fail(error); }
  });
}
export function currentState(database, storage, active) {
  return transact(database, 'readonly', context => {
    const query = context.store('state').get('current');
    query.onsuccess = context.guard(() => context.result(header(query.result, storage)));
  }, active);
}
function rawNext(body, identity) {
  if (body[0] === 0 && body.length === 57) return null;
  if (body[0] !== 1 || body.length !== 82 || body[1] >= 128) throw failure('Integrity', 'invalid raw index shape');
  const split = body[1];
  for (let bit = 0; bit < split; bit++) {
    if (((identity[bit >> 3] ^ body[2 + (bit >> 3)]) & (0x80 >> (bit & 7))) !== 0) return null;
  }
  const right = (identity[split >> 3] & (0x80 >> (split & 7))) !== 0;
  return body.slice(right ? 50 : 18, right ? 82 : 50);
}
// Everything needed for a point proof is captured in one read-only snapshot.
export function capture(database, storage, limits, identity, expectedDescriptor, expectedHead, active, promotedSibling = false) {
  return transact(database, 'readonly', context => {
    const result = {state: null, row: null, meta: null, nodes: [], transactions: 1};
    context.result(result);
    const query = context.store('state').get('current');
    query.onsuccess = context.guard(() => {
      result.state = header(query.result, storage);
      if (!equal(result.state.descriptor, expectedDescriptor) || !equal(result.state.head, expectedHead)) throw failure('Conflict', 'accepted-head-conflict');
      const row = context.store('records').get(hex(identity));
      row.onsuccess = context.guard(() => { result.row = row.result || null; if (result.row) result.meta = recordMeta(result.row, storage, limits); });
      let next = result.state.head[64] === 1 ? result.state.head.slice(65, 97) : null;
      const seen = new Set(); let sibling = null;
      const visit = () => {
        if (!next) return;
        if (result.nodes.length >= 129 || seen.has(hex(next))) throw failure('Integrity', 'invalid-path-bound');
        const hash = next; seen.add(hex(hash));
        const node = context.store('nodes').get(hex(hash));
        node.onsuccess = context.guard(() => {
          const body = nodeBytes(node.result); result.nodes.push([hash, body]); next = rawNext(body, identity);
          if (next && body[0] === 1) sibling = body.slice(equal(next, body.slice(18, 50)) ? 50 : 18, equal(next, body.slice(18, 50)) ? 82 : 50);
          if (!next && promotedSibling && body[0] === 0 && equal(body.slice(1, 17), identity) && sibling) {
            if (seen.has(hex(sibling))) throw failure('Integrity', 'invalid promoted sibling');
            const extra = context.store('nodes').get(hex(sibling));
            extra.onsuccess = context.guard(() => { result.nodes.push([sibling, nodeBytes(extra.result)]); });
          } else visit();
        });
      };
      visit();
    });
  }, active);
}
