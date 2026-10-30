export function invalid(message) { const error = new Error(message); error.code = 'InvalidInput'; return error; }

export function configuration(value) {
  if (!value || typeof value !== 'object') throw invalid('explicit host configuration required');
  const source = value.limits;
  if (!source || typeof source !== 'object') throw invalid('explicit storage limits required');
  const limits = {};
  for (const [name, minimum] of [['payload', 0], ['metadata', 0], ['records', 1]]) {
    const number = source[name];
    if (!Number.isSafeInteger(number) || number < minimum || number > 0xffffffff) throw invalid('invalid ' + name + ' limit');
    limits[name] = number;
  }
  if (source.staging !== undefined) {
    if (!Number.isSafeInteger(source.staging) || source.staging <= 0 || source.staging > 0xffffffff) throw invalid('invalid staging byte budget');
    limits.staging = source.staging;
  }
  if (limits.payload + limits.metadata + 176 > 0xffffffff) throw invalid('record frame exceeds the binding address space');
  if (!['blob', 'arraybuffer'].includes(value.storageProfile)) throw invalid('explicit blob or arraybuffer storage profile required');
  if (!Array.isArray(value.kdfProfiles) || value.kdfProfiles.length === 0) throw invalid('explicit KDF profile allowlist required');
  const kdfProfiles = value.kdfProfiles.map(profile => {
    if (!profile || !Number.isSafeInteger(profile.memory_kib) || profile.memory_kib <= 0 || profile.memory_kib > 0xffffffff ||
        !Number.isSafeInteger(profile.passes) || profile.passes <= 0 || profile.passes > 0xffffffff) throw invalid('invalid KDF profile');
    return {memory_kib: profile.memory_kib, passes: profile.passes};
  });
  if (new Set(kdfProfiles.map(profile => `${profile.memory_kib}:${profile.passes}`)).size !== kdfProfiles.length) throw invalid('duplicate KDF profile');
  let backupPolicy;
  if (value.backupPolicy !== undefined) {
    backupPolicy = {};
    for (const key of ['headerBytes', 'stanzas', 'ciphertextBytes', 'totalPlaintextBytes', 'records', 'schemaBytes', 'metadataBytes', 'payloadBytes', 'collectionBytes']) {
      const number = value.backupPolicy?.[key];
      if (!Number.isSafeInteger(number) || number < (['records', 'schemaBytes', 'metadataBytes', 'payloadBytes'].includes(key) ? 0 : 1) || number > 0xffffffff) throw invalid('invalid backup ' + key);
      backupPolicy[key] = number;
    }
    if (backupPolicy.collectionBytes < backupPolicy.ciphertextBytes + 2 * backupPolicy.totalPlaintextBytes + 65536) throw invalid('backup collection budget is below the admitted data bound');
  }
  const selected = value.access || {profiles: ['password'], maxDescriptorBytes: 276, maxDeviceSlots: 0, maxProviderBlobBytes: 0};
  if (!Array.isArray(selected.profiles) || selected.profiles.length === 0 || selected.profiles.length > 3 || new Set(selected.profiles).size !== selected.profiles.length || selected.profiles.some(profile => !['password', 'password-or-device', 'password-and-device'].includes(profile))) throw invalid('invalid admitted access profiles');
  const access = {profiles: [...selected.profiles], providers: []};
  for (const key of ['maxDescriptorBytes', 'maxDeviceSlots', 'maxProviderBlobBytes']) {
    const n = selected[key]; if (!Number.isSafeInteger(n) || n < (key === 'maxDescriptorBytes' ? 180 : 0) || n > 0xffffffff) throw invalid('invalid access ' + key);
    access[key] = n;
  }
  const registrations = value.providers || [];
  if (!Array.isArray(registrations)) throw invalid('provider registrations array required');
  for (const entry of registrations) {
    if (entry?.capability !== 'NonExportableOperation' || entry.identity?.deviceBound !== true || entry.identity?.nonexportable !== true) throw invalid('explicit qualified provider capability required');
    access.providers.push({identity: {providerId: bytes(entry.identity.providerId, 'provider ID', 16, 16), keyId: bytes(entry.identity.keyId, 'provider key ID', 16, 16), deviceBound: true, nonexportable: true}, capability: entry.capability});
  }
  const identityKey = entry => [...entry.identity.providerId, ...entry.identity.keyId].join(',');
  if (new Set(access.providers.map(identityKey)).size !== access.providers.length) throw invalid('duplicate provider registration');
  limits.descriptor = access.maxDescriptorBytes;
  return {limits, storageProfile: value.storageProfile, kdfProfiles, backupPolicy, access, providers: access.providers};
}

export function bytes(value, name, maximum, width) {
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer)) throw invalid(name + ' requires a nonshared Uint8Array');
  try { new Uint8Array(value.buffer, 0, 0); } catch { throw invalid(name + ' buffer is detached'); }
  if (value.length > maximum || width !== undefined && value.length !== width) throw invalid(name + ' length');
  return value.slice();
}

export function revision(value, insertion = false) {
  if (typeof value !== 'bigint' || value < (insertion ? 0n : 1n) || value > 9223372036854775807n) throw invalid('revision requires an exact in-range bigint');
  return value;
}
