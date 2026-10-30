import {FogVault, randomId, clearRecord} from '../dist/client.mjs';
const options = {limits: {payload: 16 * 1024 * 1024, metadata: 64, records: 4096}, storageProfile: 'arraybuffer',
  kdfProfiles: [{memory_kib: 65536, passes: 3}, {memory_kib: 65536, passes: 4}]};
const cases = [], owners = new Set(), names = new Set(), encode = value => new TextEncoder().encode(value);
const identity = new Uint8Array(16).fill(41), password = 'SYNTHETIC SDK password', changed = 'SYNTHETIC SDK changed password';
const make = () => { const owner = new FogVault(options); owners.add(owner); return owner; };
const database = () => { const name = 'fogvault-SYNTHETIC-sdk-' + crypto.randomUUID(); names.add(name); return name; };
const equal = (a, b) => a.length === b.length && a.every((byte, index) => byte === b[index]);
function require(value, message) { if (!value) throw Error(message); }
async function rejects(run, code) { try { await run(); } catch (error) { require(!code || error.code === code, `expected ${code}, received ${error.code}: ${error}`); return error; } throw Error('operation unexpectedly succeeded'); }
async function record(id, run) { try { await run(); cases.push({id, status: 'pass', executed: true}); } catch (error) { cases.push({id, status: 'fail', executed: true, error: String(error)}); throw error; } }
window.fogvaultSdkDone = (async () => {
  let failure;
  try {
    const name = database(), vault = make();
    await record('sdk_create_save_lock_reopen_read', async () => {
      await vault.create(name, password);
      const saved = await vault.save(identity, encode('synthetic metadata'), encode('SYNTHETIC SDK payload'), {expectedRevision: 0n});
      require(saved.receipt.generation === 1n, 'wrong save generation');
      await vault.lock(); await rejects(() => vault.read(identity), 'Locked');
      const reopened = make(); await reopened.open(name); await reopened.unlock(password);
      const got = await reopened.read(identity); require(got.revision === 1n && equal(got.payload, encode('SYNTHETIC SDK payload')), 'payload mismatch');
      clearRecord(got); await reopened.close();
    });
    await vault.unlock(password);
    await record('sdk_password_change_and_kdf_upgrade_survive_restart', async () => {
      const changedResult = await vault.changePassword(password, changed);
      require(changedResult.key_effect === 'Preserved', 'wrong password key effect');
      await vault.lock(); await rejects(() => vault.unlock(password), 'Authentication'); await vault.unlock(changed);
      const upgraded = await vault.upgradeKdf(changed, {memory_kib: 65536, passes: 4});
      require(upgraded.key_effect === 'Preserved', 'wrong KDF key effect');
      await vault.lock(); await vault.unlock(changed);
      const got = await vault.read(identity); require(equal(got.payload, encode('SYNTHETIC SDK payload')), 'content changed'); clearRecord(got);
    });
    await record('sdk_same_request_retry_returns_original_receipt', async () => {
      const requestId = randomId(), intent = {expectedRevision: 1n, requestId}, data = encode('SYNTHETIC updated payload');
      const first = await vault.save(identity, new Uint8Array(), data, intent);
      const repeated = await vault.save(identity, new Uint8Array(), data, intent);
      require(first.receipt.generation === repeated.receipt.generation && equal(first.receipt.head_digest, repeated.receipt.head_digest), 'retry changed receipt');
      await rejects(() => vault.save(identity, new Uint8Array(), encode('different'), intent), 'OperationIdReuse');
    });
    await record('sdk_competing_owner_cannot_refresh_stale_intent', async () => {
      const other = make(); await other.open(name); await other.unlock(changed);
      const previous = await vault.receipt();
      await other.save(identity, new Uint8Array(), encode('SYNTHETIC competing writer'), {expectedRevision: 2n});
      await rejects(() => vault.save(identity, new Uint8Array(), encode('stale'), {expectedRevision: 2n, expectedHead: previous.head_digest}), 'Conflict');
      await other.close(); await vault.lock(); await vault.unlock(changed);
    });
    await record('sdk_paged_inventory_and_delete_are_complete', async () => {
      await vault.beginRecords(); const page = await vault.recordPage(1);
      require(page.complete && page.records.length === 1 && equal(page.records[0].id, identity), 'wrong inventory');
      await vault.delete(identity, {expectedRevision: 3n}); await rejects(() => vault.read(identity), 'NotFound');
      await vault.beginRecords(); const empty = await vault.recordPage(1); require(empty.complete && empty.records.length === 0, 'deleted record remained');
    });
    await record('sdk_lock_terminates_actual_worker_kdf_before_authority_publication', async () => {
      const NativeWorker = globalThis.Worker;
      let kdfStarted;
      const started = new Promise(resolve => { kdfStarted = resolve; });
      globalThis.Worker = class ObservedWorker extends NativeWorker {
        constructor(...args) { super(...args); this.addEventListener('message', ({data}) => { if (data.progress === 'kdf-started') kdfStarted(); }); }
      };
      const owner = make();
      try {
        await owner.open(name);
        const unlocking = owner.unlock(changed), rejected = rejects(() => unlocking, 'Locked');
        await started; await owner.lock(); await rejected;
        await rejects(() => owner.read(identity), 'Locked');
      } finally { globalThis.Worker = NativeWorker; await owner.close(); }
    });
    await record('sdk_owner_recovery_reencrypts_every_record_and_survives_reopen', async () => {
      const recoverable = new FogVault({...options, limits: {...options.limits, staging: 8 * 1024 * 1024}}); owners.add(recoverable);
      const target = database(), created = await recoverable.create(target, password, {recovery: true});
      require(created.recovery_key instanceof Uint8Array && created.recovery_key.length === 80, 'missing recovery kit');
      const second = new Uint8Array(16).fill(42);
      await recoverable.save(identity, encode('first'), encode('SYNTHETIC first recovery record'), {expectedRevision: 0n});
      await recoverable.save(second, encode('second'), encode('SYNTHETIC second recovery record'), {expectedRevision: 0n});
      await recoverable.lock();
      const replacement = await recoverable.recover(created.recovery_key, changed);
      require(replacement.key_effect === 'FreshRootAndContentKeys' && replacement.anchoring === 'unanchored', 'wrong protective effect');
      require(replacement.recovery_key.length === 80 && !equal(replacement.recovery_key, created.recovery_key), 'recovery kit was not replaced');
      for (const recordId of [identity, second]) { const got = await recoverable.read(recordId); require(got.revision === 1n, 'recovery changed revision'); clearRecord(got); }
      await recoverable.lock(); await rejects(() => recoverable.unlock(password), 'Authentication'); await recoverable.unlock(changed);
      await recoverable.lock(); await rejects(() => recoverable.recover(created.recovery_key, password));
      require(recoverable.locked, 'rejected old kit retained authority'); await recoverable.unlock(changed);
      const got = await recoverable.read(identity); require(equal(got.payload, encode('SYNTHETIC first recovery record')), 'recovery content missing'); clearRecord(got);
      created.recovery_key.fill(0); replacement.recovery_key.fill(0); await recoverable.close();
    });
    await record('sdk_protective_staging_rejection_preserves_source_vault', async () => {
      const limited = new FogVault({...options, limits: {...options.limits, staging: 1}}); owners.add(limited);
      await limited.create(database(), password, {recovery: true}); await limited.save(identity, new Uint8Array(), encode('SYNTHETIC preserved record'), {expectedRevision: 0n});
      await rejects(() => limited.replaceRecovery(password, changed), 'ResourceLimit'); require(limited.locked, 'failed protective operation retained authority');
      await rejects(() => limited.unlock(changed), 'Authentication'); await limited.unlock(password);
      const got = await limited.read(identity); require(equal(got.payload, encode('SYNTHETIC preserved record')), 'staging refusal changed source'); clearRecord(got); await limited.close();
    });
    await record('sdk_recovery_reply_loss_reports_unknown_and_reopens_exact_target', async () => {
      const NativeWorker = globalThis.Worker; let owner, intercept = false;
      globalThis.Worker = class ReplyLossWorker extends NativeWorker {
        constructor(...args) { super(...args); this.addEventListener('message', event => {
          if (intercept && event.data?.ok && event.data?.result?.key_effect === 'FreshRootAndContentKeys') {
            event.stopImmediatePropagation(); void owner.lock();
          }
        }); }
      };
      try {
        owner = new FogVault({...options, limits: {...options.limits, staging: 8 * 1024 * 1024}}); owners.add(owner);
        const target = database(), created = await owner.create(target, password, {recovery: true}), requestId = randomId();
        await owner.save(identity, new Uint8Array(), encode('SYNTHETIC reply-loss record'), {expectedRevision: 0n});
        await owner.lock(); intercept = true;
        const error = await rejects(() => owner.recover(created.recovery_key, changed, requestId), 'OutcomeUnknown');
        require(equal(error.requestId, requestId), 'unknown outcome lost request identity'); intercept = false;
        await owner.unlock(changed); const reconciled = await owner.reconcileLatest(requestId);
        require(equal(reconciled.receipt.request_id, requestId), 'reconciliation accepted wrong target');
        const got = await owner.read(identity); require(equal(got.payload, encode('SYNTHETIC reply-loss record')), 'reply-loss target missing'); clearRecord(got);
        created.recovery_key.fill(0); await owner.close();
      } finally { globalThis.Worker = NativeWorker; if (owner) await owner.close(); }
    });
    await record('sdk_age_export_and_completed_fresh_restore_preserve_records', async () => {
      const policy = {headerBytes: 4096, stanzas: 4, ciphertextBytes: 4 * 1024 * 1024, totalPlaintextBytes: 4 * 1024 * 1024,
        records: 4096, schemaBytes: 0, metadataBytes: 64, payloadBytes: 1024 * 1024, collectionBytes: 16 * 1024 * 1024};
      const configuration = {...options, limits: {...options.limits, staging: 8 * 1024 * 1024}, backupPolicy: policy};
      const source = new FogVault(configuration), restored = new FogVault(configuration); owners.add(source); owners.add(restored);
      await source.create(database(), password);
      await source.save(identity, encode('metadata'), encode('SYNTHETIC backup data'), {expectedRevision: 0n});
      await source.save(identity, encode('metadata'), encode('SYNTHETIC updated backup data'), {expectedRevision: 1n});
      const key = await source.generateBackupIdentity(), exported = await source.exportBackup(key.recipient);
      require(new TextDecoder().decode(exported.ciphertext.slice(0, 22)) === 'age-encryption.org/v1\n', 'export is not standard age/v1');
      require(exported.source_header.length === 104 && exported.ciphertext_sha256.length === 32, 'export receipt missing');
      const requestId = randomId(), installed = await restored.restoreBackup(database(), exported.ciphertext, key.identity, changed,
        {kind: 'trusted-receipt', sourceHeader: exported.source_header, ciphertextSha256: exported.ciphertext_sha256}, requestId);
      require(installed.origin_verified && installed.key_effect === 'FreshRootAndContentKeys' && equal(installed.source_header, exported.source_header), 'import receipt lost source identity');
      const got = await restored.read(identity); require(got.revision === 1n && equal(got.payload, encode('SYNTHETIC updated backup data')) && equal(got.metadata, encode('metadata')), 'restored record mismatch'); clearRecord(got);
      await restored.lock(); await restored.unlock(changed); const reconciled = await restored.reconcileLatest(requestId);
      require(equal(reconciled.receipt.request_id, requestId), 'fresh import request is not reconcilable');
      const unverified = new FogVault(configuration); owners.add(unverified);
      const accepted = await unverified.restoreBackup(database(), exported.ciphertext, key.identity, changed, {kind: 'owner-accepted-unverified', sourceHeader: exported.source_header});
      require(accepted.origin_verified === false, 'unverified import was falsely origin verified');
      key.identity.fill(0); await source.close(); await restored.close(); await unverified.close();
    });
    await record('sdk_backup_authentication_failures_never_create_a_target', async () => {
      const policy = {headerBytes: 4096, stanzas: 4, ciphertextBytes: 4 * 1024 * 1024, totalPlaintextBytes: 4 * 1024 * 1024,
        records: 4096, schemaBytes: 0, metadataBytes: 64, payloadBytes: 1024 * 1024, collectionBytes: 16 * 1024 * 1024};
      const configuration = {...options, limits: {...options.limits, staging: 8 * 1024 * 1024}, backupPolicy: policy};
      const source = new FogVault(configuration); owners.add(source); await source.create(database(), password);
      await source.save(identity, new Uint8Array(), encode('SYNTHETIC backup finality data'), {expectedRevision: 0n});
      const key = await source.generateBackupIdentity(), exported = await source.exportBackup(key.recipient);
      const truncated = exported.ciphertext.slice(0, -1), trailing = new Uint8Array(exported.ciphertext.length + 1); trailing.set(exported.ciphertext);
      const tampered = exported.ciphertext.slice(); tampered[tampered.length - 1] ^= 1;
      const wrongDigest = exported.ciphertext_sha256.slice(); wrongDigest[0] ^= 1;
      for (const [ciphertext, digest] of [[truncated, exported.ciphertext_sha256], [trailing, exported.ciphertext_sha256], [tampered, exported.ciphertext_sha256], [exported.ciphertext, wrongDigest]]) {
        const destination = database(), target = new FogVault(configuration); owners.add(target);
        await rejects(() => target.restoreBackup(destination, ciphertext, key.identity, changed, {kind: 'trusted-receipt', sourceHeader: exported.source_header, ciphertextSha256: digest}), 'Integrity');
        await rejects(() => target.open(destination), 'NotFound'); await target.close();
      }
      key.identity.fill(0); await source.close();
    });
    await record('sdk_backup_restore_never_overwrites_an_existing_vault', async () => {
      const policy = {headerBytes: 4096, stanzas: 4, ciphertextBytes: 4 * 1024 * 1024, totalPlaintextBytes: 4 * 1024 * 1024,
        records: 4096, schemaBytes: 0, metadataBytes: 64, payloadBytes: 1024 * 1024, collectionBytes: 16 * 1024 * 1024};
      const configuration = {...options, limits: {...options.limits, staging: 8 * 1024 * 1024}, backupPolicy: policy};
      const existing = new FogVault(configuration), other = new FogVault(configuration); owners.add(existing); owners.add(other);
      const destination = database(); await existing.create(destination, password);
      await existing.save(identity, new Uint8Array(), encode('SYNTHETIC existing target'), {expectedRevision: 0n});
      const before = await existing.receipt(), key = await existing.generateBackupIdentity(), exported = await existing.exportBackup(key.recipient);
      await rejects(() => other.restoreBackup(destination, exported.ciphertext, key.identity, changed, {kind: 'trusted-receipt', sourceHeader: exported.source_header, ciphertextSha256: exported.ciphertext_sha256}), 'Exists');
      const after = await existing.receipt(), got = await existing.read(identity);
      require(equal(before.head_digest, after.head_digest) && equal(got.payload, encode('SYNTHETIC existing target')), 'occupied import modified target'); clearRecord(got);
      key.identity.fill(0); await existing.close(); await other.close();
    });
    // Synthetic nonextractable WebCrypto operation providers exercise the async
    // contract. Their deviceBound flag is test data, not hardware qualification.
    async function syntheticProvider(number) {
      const key = await crypto.subtle.generateKey({name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
      return {identity: {providerId: new Uint8Array(16).fill(number), keyId: new Uint8Array(16).fill(number + 1), deviceBound: true, nonexportable: true}, capability: 'NonExportableOperation',
        async wrapSeed(context, seed) { const nonce = crypto.getRandomValues(new Uint8Array(12)), ciphertext = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv: nonce, additionalData: context.authenticatedBytes}, key, seed)); const result = new Uint8Array(12 + ciphertext.length); result.set(nonce); result.set(ciphertext, 12); return result; },
        async unwrapSeed(context, wrapped) { return new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: wrapped.slice(0, 12), additionalData: context.authenticatedBytes}, key, wrapped.slice(12))); }};
    }
    function providerOptions(provider, profile) {
      return {...options, access: {profiles: ['password', profile], maxDescriptorBytes: 4096, maxDeviceSlots: 2, maxProviderBlobBytes: 256}, providers: [provider]};
    }
    await record('sdk_async_or_and_device_profiles_use_core_and_require_declared_factors', async () => {
      for (const [index, profile] of ['password-or-device', 'password-and-device'].entries()) {
        const provider = await syntheticProvider(60 + index * 2), owner = new FogVault(providerOptions(provider, profile)); owners.add(owner);
        await owner.create(database(), password, {profile, devices: [provider.identity]});
        await owner.save(identity, new Uint8Array(), encode('SYNTHETIC provider profile record'), {expectedRevision: 0n});
        const info = await owner.describeAccess(); require(info.profile === profile && info.devices.length === 1, 'wrong device profile');
        await owner.lock();
        if (profile === 'password-and-device') {
          await rejects(() => owner.unlock(password), 'UnsupportedCapability');
          await rejects(() => owner.unlockDevice(info.devices[0].slotId), 'UnsupportedCapability');
        } else { await owner.unlock(password); await owner.lock(); }
        await owner.unlockDevice(info.devices[0].slotId, profile === 'password-and-device' ? password : undefined);
        const got = await owner.read(identity); require(equal(got.payload, encode('SYNTHETIC provider profile record')), 'device payload mismatch'); clearRecord(got);
        await owner.close();
      }
    });
    await record('sdk_async_provider_failures_cannot_publish_read_authority', async () => {
      const provider = await syntheticProvider(70), owner = new FogVault(providerOptions(provider, 'password-or-device')); owners.add(owner);
      const target = database(); await owner.create(target, password, {profile: 'password-or-device', devices: [provider.identity]}); const info = await owner.describeAccess();
      await owner.lock();
      // The constructor binds provider operations, so use a shared mutable test flag.
      const failing = {...provider, async unwrapSeed() { const error = Error('SYNTHETIC denial'); error.code = 'ProviderDenied'; throw error; }};
      const denied = new FogVault(providerOptions(failing, 'password-or-device')); owners.add(denied);
      await denied.open(target);
      await rejects(() => denied.unlockDevice(info.devices[0].slotId), 'ProviderDenied'); await rejects(() => denied.read(identity), 'Locked');
      let unhandled = 0;const unexpected = event => {unhandled++;event.preventDefault();};addEventListener('unhandledrejection', unexpected);
      try {
        for (const mode of ['short', 'oversize', 'detached']) {
          const malformed = {...provider, async unwrapSeed() {
            const value = new Uint8Array(mode === 'short' ? 31 : mode === 'oversize' ? 65536 : 32);
            if (mode === 'detached') structuredClone(value.buffer, {transfer: [value.buffer]});
            return value;
          }};
          const rejected = new FogVault(providerOptions(malformed, 'password-or-device'));owners.add(rejected);await rejected.open(target);
          await rejects(() => rejected.unlockDevice(info.devices[0].slotId), 'ProviderInvalidResponse');
          await rejects(() => rejected.read(identity), 'Locked');await rejected.close();
        }
        await new Promise(resolve => setTimeout(resolve, 0));require(unhandled === 0, 'malformed provider cleanup caused an unhandled rejection');
      } finally {removeEventListener('unhandledrejection', unexpected);}
      await owner.unlock(password); await owner.close(); await denied.close();
    });
    await record('sdk_lock_cancels_async_provider_and_discards_late_completion', async () => {
      const provider = await syntheticProvider(80); let delay = false, release, began, ended, signal;
      const started = new Promise(resolve => { began = resolve; }), finished = new Promise(resolve => { ended = resolve; });
      const gate = new Promise(resolve => { release = resolve; }), original = provider.unwrapSeed;
      provider.unwrapSeed = async (context, wrapped, options) => {
        if (delay) { signal = options.signal; const copy = wrapped.slice(); began(); await gate; try { return await original(context, copy); } finally { ended(); copy.fill(0); } }
        return original(context, wrapped);
      };
      const owner = new FogVault(providerOptions(provider, 'password-or-device')); owners.add(owner);
      await owner.create(database(), password, {profile: 'password-or-device', devices: [provider.identity]}); const info = await owner.describeAccess();
      await owner.lock(); delay = true;
      const unlocking = owner.unlockDevice(info.devices[0].slotId), rejected = rejects(() => unlocking, 'Locked');
      await started; await owner.lock(); await rejected; require(signal.aborted, 'provider AbortSignal was not revoked');
      release(); await finished; require(owner.locked, 'late provider completion restored authority');
      delay = false; await owner.unlockDevice(info.devices[0].slotId); await owner.close();
    });
    async function ciphertextOf(name, recordId) {
      return new Promise((resolve, reject) => {
        const open = indexedDB.open(name); open.onerror = () => reject(open.error);
        open.onsuccess = () => {const db = open.result, tx = db.transaction('records', 'readonly'), query = tx.objectStore('records').get([...recordId].map(n => n.toString(16).padStart(2, '0')).join(''));
          let row;query.onsuccess = () => {row = query.result;};tx.oncomplete = async () => {db.close();resolve(new Uint8Array(row.envelope instanceof Blob ? await row.envelope.arrayBuffer() : row.envelope));};tx.onabort = () => {db.close();reject(tx.error);};};
      });
    }
    await record('sdk_async_access_setup_and_explicit_maintenance_preserve_record_ciphertext', async () => {
      const provider = await syntheticProvider(90), configuration = {...providerOptions(provider, 'password-or-device'), limits: {...options.limits, staging: 8 * 1024 * 1024}};
      const owner = new FogVault(configuration);owners.add(owner);const target = database();await owner.create(target, password);
      await owner.save(identity, new Uint8Array(), encode('SYNTHETIC access configuration'), {expectedRevision: 0n});const before = await ciphertextOf(target, identity);
      const graph = {password: changed, profile: 'password-or-device', devices: [provider.identity], recovery: true};
      const setup = await owner.configureAccess({kind: 'password', password}, graph);
      require(setup.key_effect === 'Preserved' && setup.recovery_key.length === 80 && equal(before, await ciphertextOf(target, identity)), 'setup changed content keys or omitted kit');
      await rejects(() => owner.configureAccess({kind: 'password', password: changed}, graph), 'UnsupportedCapability');
      const info = await owner.describeAccess();
      const maintained = await owner.maintainAccess({kind: 'device', slotId: info.devices[0].slotId}, graph);
      require(maintained.key_effect === 'Preserved' && maintained.recovery_key.length === 80 && equal(before, await ciphertextOf(target, identity)), 'maintenance changed content');
      await owner.lock();await owner.unlockDevice((await owner.describeAccess()).devices[0].slotId);
      const got = await owner.read(identity);require(equal(got.payload, encode('SYNTHETIC access configuration')), 'setup graph could not reopen');clearRecord(got);
      setup.recovery_key.fill(0);maintained.recovery_key.fill(0);await owner.close();
    });
    await record('sdk_named_lost_device_replacement_excludes_old_identity_and_changes_all_ciphertexts', async () => {
      const old = await syntheticProvider(100), replacement = await syntheticProvider(102);
      const configuration = {...options, limits: {...options.limits, staging: 8 * 1024 * 1024}, access: {profiles: ['password', 'password-or-device'], maxDescriptorBytes: 4096, maxDeviceSlots: 2, maxProviderBlobBytes: 256}, providers: [old, replacement]};
      const owner = new FogVault(configuration);owners.add(owner);const target = database();await owner.create(target, password, {profile: 'password-or-device', devices: [old.identity]});
      await owner.save(identity, new Uint8Array(), encode('SYNTHETIC lost-device record'), {expectedRevision: 0n});const before = await ciphertextOf(target, identity), oldSlot = (await owner.describeAccess()).devices[0].slotId;
      await rejects(() => owner.replaceDevice([oldSlot], {kind: 'password', password}, {password: changed, profile: 'password-or-device', devices: [old.identity], recovery: true}), 'UnsupportedCapability');
      await owner.unlock(password);require(equal(before, await ciphertextOf(target, identity)), 'refused replacement modified source');
      const completed = await owner.replaceDevice([oldSlot], {kind: 'password', password}, {password: changed, profile: 'password-or-device', devices: [replacement.identity], recovery: true});
      require(completed.key_effect === 'FreshRootAndContentKeys' && !equal(before, await ciphertextOf(target, identity)), 'replacement was only a rewrap');
      const info = await owner.describeAccess();require(info.devices.length === 1 && equal(info.devices[0].identity.keyId, replacement.identity.keyId), 'lost device remained enrolled');
      await owner.lock();await rejects(() => owner.unlockDevice(oldSlot));await owner.unlockDevice(info.devices[0].slotId);
      const got = await owner.read(identity);require(got.revision === 1n && equal(got.payload, encode('SYNTHETIC lost-device record')), 'replacement lost record');clearRecord(got);
      completed.recovery_key.fill(0);await owner.close();
    });
    await record('sdk_factor_required_recovery_builds_explicit_new_device_graph', async () => {
      const old = await syntheticProvider(110), replacement = await syntheticProvider(112);
      const configuration = {...options, limits: {...options.limits, staging: 8 * 1024 * 1024}, access: {profiles: ['password', 'password-and-device'], maxDescriptorBytes: 4096, maxDeviceSlots: 2, maxProviderBlobBytes: 256}, providers: [old, replacement]};
      const owner = new FogVault(configuration);owners.add(owner);const created = await owner.create(database(), password, {profile: 'password-and-device', devices: [old.identity], recovery: true});
      await owner.save(identity, new Uint8Array(), encode('SYNTHETIC strict recovery'), {expectedRevision: 0n});await owner.lock();
      const completed = await owner.recoverAccess(created.recovery_key, {password: changed, profile: 'password-and-device', devices: [replacement.identity], recovery: true});
      require(completed.key_effect === 'FreshRootAndContentKeys', 'strict recovery did not rotate keys');
      const info = await owner.describeAccess();require(info.profile === 'password-and-device' && equal(info.devices[0].identity.keyId, replacement.identity.keyId), 'recovery silently weakened graph');
      await owner.lock();await rejects(() => owner.unlock(changed), 'UnsupportedCapability');await owner.unlockDevice(info.devices[0].slotId, changed);
      const got = await owner.read(identity);require(equal(got.payload, encode('SYNTHETIC strict recovery')), 'strict recovery lost record');clearRecord(got);
      created.recovery_key.fill(0);completed.recovery_key.fill(0);await owner.close();
    });
    await record('sdk_factor_required_password_and_kdf_maintenance_preserve_slots_recovery_and_content', async () => {
      const provider = await syntheticProvider(120), configuration = {...providerOptions(provider, 'password-and-device'), limits: {...options.limits, staging: 8 * 1024 * 1024}};
      const owner = new FogVault(configuration);owners.add(owner);const target = database(), created = await owner.create(target, password, {profile: 'password-and-device', devices: [provider.identity], recovery: true});
      await owner.save(identity, new Uint8Array(), encode('SYNTHETIC strict maintenance'), {expectedRevision: 0n});const before = await ciphertextOf(target, identity), slot = (await owner.describeAccess()).devices[0].slotId;
      const changedResult = await owner.changePasswordWithDevice(slot, password, changed);
      require(changedResult.key_effect === 'Preserved' && equal(before, await ciphertextOf(target, identity)), 'strict password change altered content');
      await rejects(() => owner.upgradeKdfWithDevice(slot, 'SYNTHETIC wrong password', {memory_kib: 65536, passes: 4}), 'Authentication');
      const upgraded = await owner.upgradeKdfWithDevice(slot, changed, {memory_kib: 65536, passes: 4});
      require(upgraded.key_effect === 'Preserved' && equal(before, await ciphertextOf(target, identity)) && equal((await owner.describeAccess()).devices[0].slotId, slot), 'strict KDF upgrade rebuilt access graph');
      await owner.lock();await owner.unlockDevice(slot, changed);
      const repaired = await owner.recoverAccess(created.recovery_key, {password, profile: 'password-and-device', devices: [provider.identity], recovery: true});
      require(repaired.key_effect === 'FreshRootAndContentKeys', 'old recovery kit did not survive maintenance');
      const got = await owner.read(identity);require(equal(got.payload, encode('SYNTHETIC strict maintenance')), 'strict maintenance lost record');clearRecord(got);
      created.recovery_key.fill(0);repaired.recovery_key.fill(0);await owner.close();
    });
    await record('sdk_async_enrollment_preserves_existing_slots_and_recovery_with_old_device_offline', async () => {
      const old = await syntheticProvider(130), added = await syntheticProvider(132);let offline = false, oldCalls = 0, newWraps = 0;
      const unwrap = old.unwrapSeed;old.unwrapSeed = async (...args) => {oldCalls++;if (offline) {const e = Error('SYNTHETIC old device offline');e.code = 'ProviderUnavailable';throw e;}return unwrap(...args);};
      const wrap = added.wrapSeed;added.wrapSeed = async (...args) => {newWraps++;return wrap(...args);};
      const configuration = {...options, limits: {...options.limits, staging: 8 * 1024 * 1024}, access: {profiles: ['password', 'password-or-device'], maxDescriptorBytes: 4096, maxDeviceSlots: 2, maxProviderBlobBytes: 256}, providers: [old, added]};
      const owner = new FogVault(configuration);owners.add(owner);const created = await owner.create(database(), password, {profile: 'password-or-device', devices: [old.identity], recovery: true});
      await owner.save(identity, new Uint8Array(), encode('SYNTHETIC preserved enrollment'), {expectedRevision: 0n});const oldSlot = (await owner.describeAccess()).devices[0].slotId, beforeCalls = oldCalls;
      offline = true;const requestId = randomId(), result = await owner.enrollDevice({kind: 'password', password}, added.identity, requestId);
      require(result.key_effect === 'Preserved' && oldCalls === beforeCalls, 'enrollment required unavailable old device');
      const info = await owner.describeAccess();require(info.devices.length === 2 && info.devices.some(item => equal(item.slotId, oldSlot)), 'enrollment rebuilt old slots');
      const wraps = newWraps;await owner.enrollDevice({kind: 'password', password}, added.identity, requestId);require(wraps === newWraps, 'latest enrollment retry contacted provider again');
      await owner.lock();await owner.unlockDevice(info.devices.find(item => equal(item.identity.keyId, added.identity.keyId)).slotId);
      const repaired = await owner.recoverAccess(created.recovery_key, {password: changed, profile: 'password-or-device', devices: [added.identity], recovery: true});
      require(repaired.key_effect === 'FreshRootAndContentKeys', 'enrollment invalidated original recovery kit');
      created.recovery_key.fill(0);repaired.recovery_key.fill(0);await owner.close();
    });
    await record('binding_provider_replies_are_bounded_before_wasm_copy_and_phase_checked', async () => {
      const bindings = await import('../dist/wasm/fogvault_wasm.js'), wasm = await bindings.default();
      const provider = await syntheticProvider(140), registration = {identity: provider.identity, capability: 'NonExportableOperation'};
      const access = {profiles: ['password-or-device'], providers: [registration], maxDescriptorBytes: 4096, maxDeviceSlots: 1, maxProviderBlobBytes: 256};
      const creation = bindings.BrowserCreation.begin(encode(password), options.limits.payload, options.limits.metadata, options.limits.records,
        options.kdfProfiles, access, 'password-or-device', [provider.identity], false);
      try {
        const first = creation.provider_request(), large = new Uint8Array(16 * 1024 * 1024), before = wasm.memory.buffer.byteLength;
        const wrong = first.id.slice(); wrong[0] ^= 1;
        await rejects(() => creation.complete_provider(wrong, 'wrapped', large), 'Conflict');
        await rejects(() => creation.complete_provider(first.id, 'unwrapped', large), 'Conflict');
        await rejects(() => creation.complete_provider(first.id, 'wrapped', large), 'ResourceLimit');
        require(wasm.memory.buffer.byteLength === before, 'refused wrapped reply grew WASM memory');
        creation.complete_provider(first.id, 'wrapped', first.bytes);
        const next = creation.provider_request();require(next.kind === 'unwrap', 'missing roundtrip challenge');
        const nextBefore = wasm.memory.buffer.byteLength;
        await rejects(() => creation.complete_provider(next.id, 'unwrapped', large), 'ResourceLimit');
        await rejects(() => creation.complete_provider(next.id, 'unwrapped', new Uint8Array(31)), 'InvalidInput');
        const detached = new Uint8Array(32);structuredClone(detached.buffer, {transfer: [detached.buffer]});
        await rejects(() => creation.complete_provider(next.id, 'unwrapped', detached), 'InvalidInput');
        if (typeof SharedArrayBuffer === 'function') await rejects(() => creation.complete_provider(next.id, 'unwrapped', new Uint8Array(new SharedArrayBuffer(32))), 'InvalidInput');
        require(wasm.memory.buffer.byteLength === nextBefore, 'refused seed reply grew WASM memory');
        creation.complete_provider(next.id, 'unwrapped', first.bytes);
        const session = creation.finish();session.lock();session.free();first.bytes.fill(0);next.bytes.fill(0);
      } finally {creation.cancel();creation.free();}
    });
    await record('sdk_configuration_and_credentials_reject_before_transport', async () => {
      await rejects(() => Promise.resolve(new FogVault({...options, limits: {...options.limits, records: 0}})), 'InvalidInput');
      const owner = make(); await rejects(() => owner.create(database(), '\ud800'), 'InvalidInput');
      require(owner.locked, 'malformed credential published authority'); await owner.close();
    });
  } catch (error) { failure = String(error); }
  finally {
    await Promise.all([...owners].map(owner => owner.close()));
    await Promise.all([...names].map(name => new Promise(resolve => { const request = indexedDB.deleteDatabase(name); request.onsuccess = request.onerror = request.onblocked = resolve; })));
  }
  const result = {schema: 'fogvault-browser-sdk-acceptance/v1', pass: !failure, cases, error: failure, user_agent: navigator.userAgent};
  document.querySelector('#result').textContent = JSON.stringify(result, null, 2); return result;
})();
