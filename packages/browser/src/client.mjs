import {configuration, bytes, revision, invalid} from './configuration.mjs';
import {passwordTextToBytes} from './password.mjs';

const MUTATING = new Set(['create', 'save_at', 'delete_at', 'change_password', 'upgrade_kdf', 'recover', 'protective_replace', 'restore_backup', 'access_change', 'credential_access']);
const PASSWORD_FIELDS = ['password', 'new_password', 'recovery_key', 'identity'];

export class FogVaultError extends Error {
  constructor(code, message, requestId) {
    super(message); this.name = 'FogVaultError'; this.code = code;
    if (requestId) this.requestId = requestId.slice();
  }
}

export function randomId() { return crypto.getRandomValues(new Uint8Array(16)); }
export {passwordTextToBytes};

function password(value) { return typeof value === 'string' ? passwordTextToBytes(value) : bytes(value, 'password', 0xffffffff); }
function clearOwnedBytes(value) {
  if (value instanceof Uint8Array && value.buffer instanceof ArrayBuffer) {
    try { value.fill(0); } catch { /* A foreign callback can detach its borrowed/result buffer. */ }
  }
}
function wipe(args) { for (const key of PASSWORD_FIELDS) clearOwnedBytes(args[key]); }
function name(value) { if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) throw invalid('nonempty database name required'); return value; }
function cloneReceipt(value) { return value && {generation: value.generation, request_id: value.request_id.slice(), head_digest: value.head_digest.slice()}; }

/** One vault owner, one dedicated Worker. The caller chooses finite host policy. */
export class FogVault {
  #configuration; #workerUrl; #worker = null; #ready = null; #rejectReady = null;
  #providers = new Map(); #providerControllers = new Map();
  #channel; #epoch = 0; #sequence = 0; #pending = new Map(); #busy = false;
  #name = null; #opened = false; #unlocked = false; #closed = false; #receipt = null;

  constructor(options) {
    this.#configuration = configuration(options);
    for (const provider of options.providers || []) {
      if (typeof provider.wrapSeed !== 'function' || typeof provider.unwrapSeed !== 'function') throw invalid('registered async wrapSeed/unwrapSeed operations required');
      const identity = provider.identity;
      this.#providers.set(this.#providerKey(identity), {wrapSeed: provider.wrapSeed.bind(provider), unwrapSeed: provider.unwrapSeed.bind(provider)});
    }
    this.#workerUrl = options.workerUrl || new URL('./worker.mjs', import.meta.url);
    this.#channel = [...randomId()].map(byte => byte.toString(16).padStart(2, '0')).join('');
  }

  get locked() { return !this.#unlocked; }
  get closed() { return this.#closed; }
  capabilities() {
    return Object.freeze({storage: 'indexeddb', freshness: 'unanchored', accessProfiles: Object.freeze([...this.#configuration.access.profiles]),
      recovery: !!this.#configuration.limits.staging, deviceProviders: this.#providers.size > 0 && this.#configuration.access.maxDeviceSlots > 0 && this.#configuration.access.maxProviderBlobBytes > 0 && this.#configuration.access.profiles.some(profile => profile !== 'password'), encryptedExports: !!this.#configuration.backupPolicy});
  }

  #providerKey(identity) { return [...identity.providerId].map(n => n.toString(16).padStart(2, '0')).join('') + ':' + [...identity.keyId].map(n => n.toString(16).padStart(2, '0')).join(''); }

  #failure(code, message, requestId) { return new FogVaultError(code, message, requestId); }

  #stop(code = 'Locked', message = 'vault owner was locked') {
    this.#epoch++;
    for (const entry of this.#providerControllers.values()) entry.controller.abort();
    this.#providerControllers.clear();
    this.#unlocked = false; this.#opened = false; this.#receipt = null; this.#busy = false;
    const worker = this.#worker; this.#worker = null;
    if (worker) worker.terminate();
    const failure = this.#failure(code, message);
    this.#rejectReady?.(failure); this.#rejectReady = null; this.#ready = null;
    for (const pending of this.#pending.values()) {
      if (MUTATING.has(pending.action)) pending.reject(this.#failure('OutcomeUnknown', 'mutation reply was lost; reopen and reconcile the request', pending.request));
      else pending.reject(failure);
    }
    this.#pending.clear();
  }

  #spawn() {
    if (this.#closed) throw this.#failure('StorageClosed', 'vault owner is closed');
    if (this.#worker) return this.#ready;
    const epoch = this.#epoch, worker = new Worker(this.#workerUrl, {type: 'module', name: 'fogvault'});
    this.#worker = worker;
    this.#ready = new Promise((resolve, reject) => {
      this.#rejectReady = reject;
      worker.onmessage = ({data}) => {
        if (worker !== this.#worker || epoch !== this.#epoch || data?.channel !== this.#channel) return;
        if (data.initializationFailed) { this.#stop(data.code, data.error); return; }
        if (data.ready) { this.#rejectReady = null; resolve(); return; }
        if (data.provider_cancel) {
          this.#providerControllers.get(data.provider_cancel.id)?.controller.abort(); return;
        }
        if (data.provider_request) { void this.#providerReply(worker, epoch, data); return; }
        if (data.progress) return;
        const pending = this.#pending.get(data.requestId);
        if (!pending) return;
        this.#pending.delete(data.requestId);
        if (data.ok) pending.resolve(data.result);
        else pending.reject(this.#failure(data.code || 'Storage', data.error || 'worker operation failed', data.request_id));
      };
      worker.onerror = event => { event.preventDefault?.(); if (worker === this.#worker) this.#stop('StorageClosed', event.message || 'worker failed'); };
      worker.onmessageerror = () => { if (worker === this.#worker) this.#stop('StorageClosed', 'worker response could not be cloned'); };
      try { worker.postMessage({action: 'initialize', channel: this.#channel, configuration: this.#configuration}); }
      catch (error) { this.#stop('StorageClosed', String(error)); }
    });
    // A lock can reject readiness before the method reaches its await.
    this.#ready.catch(() => {});
    return this.#ready;
  }

  async #providerReply(worker, epoch, message) {
    const request = message.provider_request;
    if (!this.#pending.has(message.parent_request) || !(request.id instanceof Uint8Array) || request.id.length !== 16 || !['wrap', 'unwrap'].includes(request.kind)) return;
    const token = [...request.id].map(n => n.toString(16).padStart(2, '0')).join('');
    const controller = new AbortController();
    const pending = {controller}; this.#providerControllers.set(token, pending);
    const clearInput = () => clearOwnedBytes(request.bytes);
    controller.signal.addEventListener('abort', clearInput, {once: true});
    let output, response;
    try {
      const provider = this.#providers.get(this.#providerKey(request.context.identity));
      if (!provider) throw this.#failure('ProviderUnavailable', 'provider identity is not registered');
      output = await provider[request.kind === 'wrap' ? 'wrapSeed' : 'unwrapSeed'](request.context, request.bytes, {signal: controller.signal});
      const maximum = request.kind === 'wrap' ? this.#configuration.access.maxProviderBlobBytes : 32;
      response = bytes(output, 'provider result', maximum, request.kind === 'unwrap' ? 32 : undefined);
      if (controller.signal.aborted || epoch !== this.#epoch || worker !== this.#worker) return;
      worker.postMessage({channel: this.#channel, action: 'provider_response', args: {id: token, kind: request.kind === 'wrap' ? 'wrapped' : 'unwrapped', bytes: response}});
    } catch (error) {
      if (controller.signal.aborted || epoch !== this.#epoch || worker !== this.#worker) return;
      const admitted = ['Cancelled', 'ProviderDenied', 'ProviderUnavailable', 'ProviderIdentityChanged', 'UnsupportedCapability', 'ProviderInvalidResponse'];
      const kind = error?.name === 'AbortError' ? 'Cancelled' : error?.code === 'InvalidInput' ? 'ProviderInvalidResponse' : admitted.includes(error?.code) ? error.code : 'ProviderFailure';
      try { worker.postMessage({channel: this.#channel, action: 'provider_response', args: {id: token, kind, bytes: new Uint8Array()}}); }
      catch { if (worker === this.#worker) this.#stop('StorageClosed', 'provider response transport failed'); }
    } finally {
      clearInput(); clearOwnedBytes(response);
      // Callback results transfer ownership to the SDK; unwrap seeds are secret.
      clearOwnedBytes(output);
      if (this.#providerControllers.get(token) === pending) this.#providerControllers.delete(token);
    }
  }

  async #send(action, args, epoch) {
    await this.#spawn();
    if (epoch !== this.#epoch || !this.#worker) throw this.#failure('StaleSession', 'operation was revoked before transport');
    const requestId = ++this.#sequence;
    return new Promise((resolve, reject) => {
      this.#pending.set(requestId, {resolve, reject, action, request: args.request?.slice()});
      try { this.#worker.postMessage({channel: this.#channel, requestId, action, args}); }
      catch (error) { this.#pending.delete(requestId); reject(this.#failure('Storage', 'operation was not submitted: ' + String(error))); }
      finally { wipe(args); }
    });
  }

  async #run(callback, owned = {}) {
    if (this.#closed) { wipe(owned); throw this.#failure('StorageClosed', 'vault owner is closed'); }
    if (this.#busy) { wipe(owned); throw this.#failure('Conflict', 'another operation is in progress'); }
    this.#busy = true; const epoch = this.#epoch;
    try { return await callback(epoch); }
    finally { wipe(owned); if (epoch === this.#epoch) this.#busy = false; }
  }

  #requireUnlocked() { if (!this.#unlocked) throw this.#failure('Locked', 'vault is locked'); }
  #accept(result) {
    if (result.receipt) this.#receipt = cloneReceipt(result.receipt);
    else if (result.head_digest) this.#receipt = cloneReceipt(result);
    return result;
  }
  #mutation(identity, options, insertion) {
    this.#requireUnlocked();
    if (!options || typeof options !== 'object') throw invalid('explicit expected revision required');
    const head = options.expectedHead || this.#receipt?.head_digest;
    return {id: bytes(identity, 'record ID', 16, 16), expected: revision(options.expectedRevision, insertion),
      expected_head: bytes(head, 'expected head', 32, 32), request: options.requestId === undefined ? randomId() : bytes(options.requestId, 'request ID', 16, 16)};
  }

  create(databaseName, credential, options = {}) {
    if (options.recovery === true && !this.#configuration.limits.staging) throw this.#failure('UnsupportedCapability', 'recovery requires an explicit staging budget');
    const profile = options.profile ?? 'password';
    if (!this.#configuration.access.profiles.includes(profile)) throw this.#failure('UnsupportedCapability', 'access profile is not admitted by the host');
    const devices = (options.devices || []).map(identity => {
      const registered = this.#configuration.access.providers.find(entry => this.#providerKey(entry.identity) === this.#providerKey(identity));
      if (!registered) throw this.#failure('UnsupportedCapability', 'unregistered device identity');
      return {...registered.identity, providerId: registered.identity.providerId.slice(), keyId: registered.identity.keyId.slice()};
    });
    const args = {name: name(databaseName), password: password(credential), recovery: options.recovery === true, profile, devices};
    return this.#run(async epoch => {
      this.#unlocked = false; this.#receipt = null; this.#name = args.name;
      const result = await this.#send('create', args, epoch);
      this.#opened = true; this.#unlocked = true; return this.#accept(result);
    }, args);
  }

  open(databaseName) {
    const args = {name: name(databaseName)};
    return this.#run(async epoch => {
      this.#unlocked = false; this.#receipt = null; this.#name = args.name;
      const result = await this.#send('open', args, epoch); this.#opened = true; return result;
    });
  }

  unlock(credential) {
    const args = {password: password(credential)};
    return this.#run(async epoch => {
      if (!this.#name) throw invalid('open or create a named vault first');
      this.#unlocked = false; this.#receipt = null;
      if (!this.#opened) { await this.#send('open', {name: this.#name}, epoch); this.#opened = true; }
      const result = await this.#send('unlock', args, epoch); this.#unlocked = true; return this.#accept(result);
    }, args);
  }

  describeAccess() {
    return this.#run(async epoch => {
      if (!this.#name) throw invalid('open a named vault first');
      if (!this.#opened) { await this.#send('open', {name: this.#name}, epoch); this.#opened = true; }
      return this.#send('access_info', {}, epoch);
    });
  }
  unlockDevice(slotId, credential) {
    const args = {slot: bytes(slotId, 'device slot', 16, 16)};
    if (credential !== undefined && credential !== null) args.password = password(credential);
    return this.#run(async epoch => {
      if (!this.#name) throw invalid('open a named vault first');
      this.#unlocked = false; this.#receipt = null;
      if (!this.#opened) { await this.#send('open', {name: this.#name}, epoch); this.#opened = true; }
      const result = await this.#send('unlock_device', args, epoch); this.#unlocked = true; return this.#accept(result);
    }, args);
  }

  /** Revokes this owner immediately, including a synchronous Worker KDF. */
  lock() { this.#stop(); return Promise.resolve({locked: true}); }
  close() { this.#stop('StorageClosed', 'vault owner was closed'); this.#closed = true; this.#name = null; return Promise.resolve({closed: true}); }

  save(identity, metadata, payload, options) {
    const args = this.#mutation(identity, options, true);
    args.metadata = bytes(metadata, 'metadata', this.#configuration.limits.metadata);
    args.payload = bytes(payload, 'payload', this.#configuration.limits.payload);
    return this.#run(async epoch => this.#accept(await this.#send('save_at', args, epoch)));
  }
  delete(identity, options) {
    const args = this.#mutation(identity, options, false);
    return this.#run(async epoch => this.#accept(await this.#send('delete_at', args, epoch)));
  }
  read(identity) {
    this.#requireUnlocked(); const args = {id: bytes(identity, 'record ID', 16, 16)};
    return this.#run(epoch => this.#send('read', args, epoch));
  }
  receipt() {
    this.#requireUnlocked(); return this.#run(async epoch => this.#accept(await this.#send('receipt', {}, epoch)));
  }
  beginRecords() {
    this.#requireUnlocked(); return this.#run(async epoch => this.#accept(await this.#send('begin_records', {}, epoch)));
  }
  recordPage(maximum) {
    this.#requireUnlocked();
    if (!Number.isSafeInteger(maximum) || maximum <= 0 || maximum > this.#configuration.limits.records) throw invalid('invalid record page size');
    return this.#run(epoch => this.#send('record_page', {maximum}, epoch));
  }
  cancelRecords() { this.#requireUnlocked(); return this.#run(epoch => this.#send('cancel_records', {}, epoch)); }

  changePassword(oldCredential, newCredential, requestId = randomId()) {
    this.#requireUnlocked(); const args = {request: bytes(requestId, 'request ID', 16, 16), password: password(oldCredential)};
    try { args.new_password = password(newCredential); } catch (error) { wipe(args); throw error; }
    return this.#run(async epoch => this.#accept(await this.#send('change_password', args, epoch)), args);
  }
  upgradeKdf(credential, target, requestId = randomId()) {
    this.#requireUnlocked();
    const selected = this.#configuration.kdfProfiles.find(profile => profile.memory_kib === target?.memory_kib && profile.passes === target?.passes);
    if (!selected) throw this.#failure('ResourceLimit', 'KDF target is not in the host allowlist');
    const args = {password: password(credential), target: {...selected}, request: bytes(requestId, 'request ID', 16, 16)};
    return this.#run(async epoch => this.#accept(await this.#send('upgrade_kdf', args, epoch)), args);
  }
  #target(target) {
    if (!target || !this.#configuration.access.profiles.includes(target.profile) || typeof target.recovery !== 'boolean' || !Array.isArray(target.devices)) throw invalid('explicit admitted target graph required');
    if (target.devices.length > this.#configuration.access.maxDeviceSlots) throw this.#failure('ResourceLimit', 'target device count exceeds host admission');
    const devices = target.devices.map(identity => {
      const registered = this.#configuration.access.providers.find(entry => this.#providerKey(entry.identity) === this.#providerKey(identity));
      if (!registered) throw this.#failure('UnsupportedCapability', 'target provider is not registered');
      return {...registered.identity, providerId: registered.identity.providerId.slice(), keyId: registered.identity.keyId.slice()};
    });
    return {profile: target.profile, devices, recovery: target.recovery, new_password: password(target.password)};
  }
  #accessChange(mode, source, target, removedSlots, requestId) {
    if (mode !== 'recovery') this.#requireUnlocked();
    if (['protective', 'device', 'recovery'].includes(mode) && !this.#configuration.limits.staging) throw this.#failure('UnsupportedCapability', 'protective staging budget required');
    const args = {mode, request: bytes(requestId, 'request ID', 16, 16), ...this.#target(target)};
    try {
      if (mode === 'recovery') args.recovery_key = bytes(source, 'recovery key', 80, 80);
      else if (source?.kind === 'password') args.password = password(source.password);
      else if (source?.kind === 'device') {
        args.source_slot = bytes(source.slotId, 'source device slot', 16, 16);
        if (source.password !== undefined && source.password !== null) args.password = password(source.password);
      } else throw invalid('explicit source access path required');
      if (mode === 'device') {
        if (!Array.isArray(removedSlots) || removedSlots.length > this.#configuration.access.maxDeviceSlots) throw invalid('bounded removed device slots required');
        args.removed_slots = removedSlots.map(slot => bytes(slot, 'removed device slot', 16, 16));
      }
    } catch (error) {wipe(args);throw error;}
    return this.#run(async epoch => {
      if (mode === 'recovery') {
        if (!this.#name) throw invalid('open the recovery target first');
        this.#unlocked = false;this.#receipt = null;
        if (!this.#opened) {await this.#send('open', {name: this.#name}, epoch);this.#opened = true;}
      }
      try {
        const result = await this.#send('access_change', args, epoch);
        if (mode === 'recovery') this.#unlocked = true;
        return this.#accept(result);
      } catch (error) {if (['protective', 'device', 'recovery'].includes(mode)) this.#stop();throw error;}
    }, args);
  }
  enrollDevice(source, identity, requestId = randomId()) {
    this.#requireUnlocked();
    const registered = this.#configuration.access.providers.find(entry => this.#providerKey(entry.identity) === this.#providerKey(identity));
    if (!registered) throw this.#failure('UnsupportedCapability', 'new provider identity is not registered');
    const args = {mode: 'enroll', profile: 'password', devices: [{...registered.identity, providerId: registered.identity.providerId.slice(), keyId: registered.identity.keyId.slice()}],
      recovery: false, new_password: new Uint8Array(), request: bytes(requestId, 'request ID', 16, 16)};
    if (source?.kind === 'password') args.password = password(source.password);
    else if (source?.kind === 'device') {args.source_slot = bytes(source.slotId, 'source device slot', 16, 16);if (source.password !== undefined && source.password !== null) args.password = password(source.password);}
    else throw invalid('explicit source access path required');
    return this.#run(async epoch => this.#accept(await this.#send('access_change', args, epoch)), args);
  }
  configureAccess(source, target, requestId = randomId()) {return this.#accessChange('configure', source, target, [], requestId);}
  maintainAccess(source, target, requestId = randomId()) {return this.#accessChange('maintenance', source, target, [], requestId);}
  protectAccess(source, target, requestId = randomId()) {return this.#accessChange('protective', source, target, [], requestId);}
  replaceDevice(removedSlots, source, target, requestId = randomId()) {return this.#accessChange('device', source, target, removedSlots, requestId);}
  recoverAccess(recoveryKey, target, requestId = randomId()) {return this.#accessChange('recovery', recoveryKey, target, [], requestId);}
  changePasswordWithDevice(slotId, oldCredential, newCredential, requestId = randomId()) {
    this.#requireUnlocked();
    const args = {kind: 'password', source_slot: bytes(slotId, 'device slot', 16, 16), password: password(oldCredential), request: bytes(requestId, 'request ID', 16, 16)};
    try {args.new_password = password(newCredential);} catch (error) {wipe(args);throw error;}
    return this.#run(async epoch => this.#accept(await this.#send('credential_access', args, epoch)), args);
  }
  upgradeKdfWithDevice(slotId, credential, target, requestId = randomId()) {
    this.#requireUnlocked();
    const admitted = this.#configuration.kdfProfiles.find(profile => profile.memory_kib === target?.memory_kib && profile.passes === target?.passes);
    if (!admitted) throw this.#failure('ResourceLimit', 'KDF target is not admitted');
    const args = {kind: 'kdf', source_slot: bytes(slotId, 'device slot', 16, 16), password: password(credential), target: {...admitted}, request: bytes(requestId, 'request ID', 16, 16)};
    return this.#run(async epoch => this.#accept(await this.#send('credential_access', args, epoch)), args);
  }
  generateBackupIdentity() {
    if (!this.#configuration.backupPolicy) throw this.#failure('UnsupportedCapability', 'explicit backup policy required');
    return this.#run(epoch => this.#send('backup_identity', {}, epoch));
  }
  exportBackup(recipient) {
    this.#requireUnlocked();
    if (!this.#configuration.backupPolicy) throw this.#failure('UnsupportedCapability', 'explicit backup policy required');
    if (typeof recipient !== 'string') throw invalid('age recipient text required');
    return this.#run(epoch => this.#send('backup_export', {recipient}, epoch));
  }
  restoreBackup(databaseName, ciphertext, identity, newCredential, approval, requestId = randomId()) {
    const policy = this.#configuration.backupPolicy;
    if (!policy || !this.#configuration.limits.staging) throw this.#failure('UnsupportedCapability', 'explicit backup and staging policies required');
    if (!approval || !['trusted-receipt', 'owner-accepted-unverified'].includes(approval.kind)) throw invalid('explicit import origin approval required');
    const args = {name: name(databaseName), ciphertext: bytes(ciphertext, 'backup ciphertext', policy.ciphertextBytes),
      source_header: bytes(approval.sourceHeader, 'source header', 104, 104), request: bytes(requestId, 'request ID', 16, 16),
      trusted_digest: approval.kind === 'trusted-receipt' ? bytes(approval.ciphertextSha256, 'trusted ciphertext digest', 32, 32) : null,
      owner_accepted_unverified: approval.kind === 'owner-accepted-unverified', identity: password(identity)};
    try { args.new_password = password(newCredential); } catch (error) { wipe(args); throw error; }
    return this.#run(async epoch => {
      this.#name = args.name; this.#opened = false; this.#unlocked = false; this.#receipt = null;
      try {
        const result = await this.#send('restore_backup', args, epoch); this.#opened = true; this.#unlocked = true; return this.#accept(result);
      } catch (error) { this.#stop(); throw error; }
    }, args);
  }
  recover(recoveryKey, newCredential, requestId = randomId()) {
    if (!this.#configuration.limits.staging) throw this.#failure('UnsupportedCapability', 'recovery requires an explicit staging budget');
    const args = {recovery_key: bytes(recoveryKey, 'recovery key', 80, 80), request: bytes(requestId, 'request ID', 16, 16)};
    try { args.new_password = password(newCredential); } catch (error) { args.recovery_key.fill(0); throw error; }
    return this.#run(async epoch => {
      this.#unlocked = false; this.#receipt = null;
      try {
        if (!this.#name) throw invalid('open the recovery target first');
        if (!this.#opened) { await this.#send('open', {name: this.#name}, epoch); this.#opened = true; }
        const result = await this.#send('recover', args, epoch); this.#unlocked = true; return this.#accept(result);
      } catch (error) { this.#stop(); throw error; }
    }, args).finally(() => args.recovery_key.fill(0));
  }
  replaceRecovery(oldCredential, newCredential, requestId = randomId()) {
    this.#requireUnlocked();
    if (!this.#configuration.limits.staging) throw this.#failure('UnsupportedCapability', 'protective replacement requires an explicit staging budget');
    const args = {password: password(oldCredential), request: bytes(requestId, 'request ID', 16, 16)};
    try { args.new_password = password(newCredential); } catch (error) { wipe(args); throw error; }
    return this.#run(async epoch => {
      try { return this.#accept(await this.#send('protective_replace', args, epoch)); }
      catch (error) { this.#stop(); throw error; }
    }, args);
  }
  reconcileLatest(requestId) {
    this.#requireUnlocked(); const args = {request: bytes(requestId, 'request ID', 16, 16)};
    return this.#run(async epoch => this.#accept(await this.#send('reconcile_latest', args, epoch)));
  }
}

export function clearRecord(record) { record.metadata.fill(0); record.payload.fill(0); }
