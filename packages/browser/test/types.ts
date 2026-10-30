import {FogVault, clearRecord, randomId, type KeyProvider, type AccessSource} from '@datafog/fogvault-browser';

const vault = new FogVault({
  limits: {payload: 4096, metadata: 128, records: 16},
  storageProfile: 'arraybuffer',
  kdfProfiles: [{memory_kib: 65536, passes: 3}],
});

async function consumer(password: Uint8Array) {
  await vault.create('synthetic-type-consumer', password);
  const id = randomId();
  const saved = await vault.save(id, new Uint8Array(), new Uint8Array(), {expectedRevision: 0n});
  const revision: bigint = saved.receipt.generation;
  const record = await vault.read(id);
  clearRecord(record);
  await vault.delete(id, {expectedRevision: 1n});
  await vault.lock();
  await vault.close();
  // @ts-expect-error revisions must remain exact bigint values at the boundary.
  await vault.save(id, new Uint8Array(), new Uint8Array(), {expectedRevision: 1});
  // @ts-expect-error the supported owner exposes no raw vault-root key getter.
  vault.rootKey();
  return revision;
}

const provider: KeyProvider = {
  identity: {providerId: new Uint8Array(16), keyId: new Uint8Array(16), deviceBound: true, nonexportable: true},
  capability: 'NonExportableOperation',
  async wrapSeed(context, seed, {signal}) {
    const epoch: bigint = context.rootEpoch;
    void epoch; void seed; void signal;
    throw new Error('type-only fixture; no device implementation');
  },
  async unwrapSeed(context, wrapped, {signal}) {
    void context; void wrapped; void signal;
    throw new Error('type-only fixture; no device implementation');
  },
};
const auth: AccessSource = {kind: 'device', slotId: new Uint8Array(16), password: 'SYNTHETIC'};
void consumer; void provider; void auth;
