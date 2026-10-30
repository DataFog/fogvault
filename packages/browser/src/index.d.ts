export interface KdfProfile { memory_kib: number; passes: number }
export interface Limits { payload: number; metadata: number; records: number; staging?: number }
export interface FogVaultOptions {
  limits: Limits;
  kdfProfiles: readonly KdfProfile[];
  storageProfile: 'blob' | 'arraybuffer';
  workerUrl?: string | URL;
  backupPolicy?: BackupPolicy;
  access?: AccessPolicy;
  providers?: readonly KeyProvider[];
}
export type AccessProfile = 'password' | 'password-or-device' | 'password-and-device';
export interface ProviderIdentity {providerId: Uint8Array; keyId: Uint8Array; deviceBound: true; nonexportable: true}
export interface ProviderContext {vaultId: Uint8Array; rootEpoch: bigint; slotId: Uint8Array; slotRevision: bigint; identity: ProviderIdentity; authenticatedBytes: Uint8Array}
export interface AccessPolicy {profiles: readonly AccessProfile[]; maxDescriptorBytes: number; maxDeviceSlots: number; maxProviderBlobBytes: number}
export interface KeyProvider {
  identity: ProviderIdentity;
  /** Host-qualified declaration, not hardware attestation supplied by the SDK. */
  capability: 'NonExportableOperation';
  /** Inputs are borrowed until completion/cancellation; returned buffers transfer to the SDK and are wiped. */
  wrapSeed(context: ProviderContext, seed: Uint8Array, options: {signal: AbortSignal}): Promise<Uint8Array>;
  unwrapSeed(context: ProviderContext, wrapped: Uint8Array, options: {signal: AbortSignal}): Promise<Uint8Array>;
}
export type AccessSource = {kind: 'password'; password: Password} | {kind: 'device'; slotId: Uint8Array; password?: Password};
export interface AccessTarget {password: Password; profile: AccessProfile; devices: readonly ProviderIdentity[]; recovery: boolean}
export interface AccessChangeResult {receipt: Receipt; key_effect: 'Preserved' | 'FreshRootAndContentKeys'; recovery_key?: Uint8Array | null; anchoring?: 'unanchored'}
export interface BackupPolicy {
  headerBytes: number; stanzas: number; ciphertextBytes: number; totalPlaintextBytes: number;
  records: number; schemaBytes: number; metadataBytes: number; payloadBytes: number;
  /** At least ciphertextBytes + 2 * totalPlaintextBytes + 65536; excludes runtime/allocator/foreign copies. */
  collectionBytes: number;
}
export interface BackupResult { ciphertext: Uint8Array; source_header: Uint8Array; ciphertext_sha256: Uint8Array; ciphertext_bytes: bigint }
export type ImportApproval = {kind: 'trusted-receipt'; sourceHeader: Uint8Array; ciphertextSha256: Uint8Array}
  | {kind: 'owner-accepted-unverified'; sourceHeader: Uint8Array};
export interface ImportResult { imported: true; receipt: Receipt; source_header: Uint8Array; origin_verified: boolean; key_effect: 'FreshRootAndContentKeys'; record_revision_policy: 'new-vault-starts-at-one'; anchoring: 'unanchored' }
export interface Receipt { generation: bigint; request_id: Uint8Array; head_digest: Uint8Array }
export interface MutationOptions {
  /** Zero inserts, a positive revision updates. Always use bigint. */
  expectedRevision: bigint;
  /** Defaults to the owner's last accepted head, captured before transport. */
  expectedHead?: Uint8Array;
  requestId?: Uint8Array;
}
export interface StoredRecord { revision: bigint; metadata: Uint8Array; payload: Uint8Array }
export interface RecordPage {
  records: {id: Uint8Array; revision: bigint}[];
  complete: boolean;
  receipt: Receipt;
  stats: Record<string, number>;
}
export interface MutationResult { receipt: Receipt; replay: boolean; saved?: boolean; deleted?: boolean }
export interface CredentialResult { receipt: Receipt; key_effect: 'Preserved' }
export class FogVaultError extends Error { code: string; requestId?: Uint8Array }
export type Password = string | Uint8Array;
export function randomId(): Uint8Array;
export function passwordTextToBytes(text: string): Uint8Array;
/** Clear caller-owned record buffers when they are no longer needed. */
export function clearRecord(record: StoredRecord): void;
export class FogVault {
  constructor(options: FogVaultOptions);
  readonly locked: boolean;
  readonly closed: boolean;
  capabilities(): Readonly<{storage: 'indexeddb'; freshness: 'unanchored'; accessProfiles: readonly AccessProfile[]; recovery: boolean; deviceProviders: boolean; encryptedExports: boolean}>;
  create(name: string, password: Password, options?: {recovery?: boolean; profile?: AccessProfile; devices?: readonly ProviderIdentity[]}): Promise<{created: true; receipt: Receipt; recovery_key?: Uint8Array}>;
  open(name: string): Promise<{opened: true}>;
  unlock(password: Password): Promise<{unlocked: true; receipt: Receipt}>;
  describeAccess(): Promise<{profile: AccessProfile; recovery: boolean; rootEpoch: bigint; devices: {slotId: Uint8Array; identity: ProviderIdentity}[]}>;
  unlockDevice(slotId: Uint8Array, password?: Password): Promise<{unlocked: true; receipt: Receipt}>;
  /** Immediate owner revocation and Worker termination, including in-flight KDFs. */
  lock(): Promise<{locked: true}>;
  /** Permanently dispose this owner. Create another instance to reopen. */
  close(): Promise<{closed: true}>;
  save(id: Uint8Array, metadata: Uint8Array, payload: Uint8Array, options: MutationOptions): Promise<MutationResult>;
  delete(id: Uint8Array, options: MutationOptions): Promise<MutationResult>;
  read(id: Uint8Array): Promise<StoredRecord>;
  receipt(): Promise<Receipt>;
  beginRecords(): Promise<{cursor: true; receipt: Receipt}>;
  recordPage(maximum: number): Promise<RecordPage>;
  cancelRecords(): Promise<{cancelled: true}>;
  changePassword(oldPassword: Password, newPassword: Password, requestId?: Uint8Array): Promise<CredentialResult>;
  upgradeKdf(password: Password, target: KdfProfile, requestId?: Uint8Array): Promise<CredentialResult>;
  enrollDevice(source: AccessSource, identity: ProviderIdentity, requestId?: Uint8Array): Promise<AccessChangeResult>;
  configureAccess(source: AccessSource, target: AccessTarget, requestId?: Uint8Array): Promise<AccessChangeResult>;
  maintainAccess(source: AccessSource, target: AccessTarget, requestId?: Uint8Array): Promise<AccessChangeResult>;
  protectAccess(source: AccessSource, target: AccessTarget, requestId?: Uint8Array): Promise<AccessChangeResult>;
  replaceDevice(removedSlots: readonly Uint8Array[], source: AccessSource, target: AccessTarget, requestId?: Uint8Array): Promise<AccessChangeResult>;
  recoverAccess(recoveryKey: Uint8Array, target: AccessTarget, requestId?: Uint8Array): Promise<AccessChangeResult>;
  changePasswordWithDevice(slotId: Uint8Array, oldPassword: Password, newPassword: Password, requestId?: Uint8Array): Promise<CredentialResult>;
  upgradeKdfWithDevice(slotId: Uint8Array, password: Password, target: KdfProfile, requestId?: Uint8Array): Promise<CredentialResult>;
  generateBackupIdentity(): Promise<{identity: Uint8Array; recipient: string}>;
  exportBackup(recipient: string): Promise<BackupResult>;
  restoreBackup(name: string, ciphertext: Uint8Array, identity: Password, newPassword: Password, approval: ImportApproval, requestId?: Uint8Array): Promise<ImportResult>;
  recover(recoveryKey: Uint8Array, newPassword: Password, requestId?: Uint8Array): Promise<{receipt: Receipt; key_effect: 'FreshRootAndContentKeys'; recovery_key: Uint8Array; anchoring: 'unanchored'}>;
  replaceRecovery(oldPassword: Password, newPassword: Password, requestId?: Uint8Array): Promise<{receipt: Receipt; key_effect: 'FreshRootAndContentKeys'; recovery_key: Uint8Array; anchoring: 'unanchored'}>;
  reconcileLatest(requestId: Uint8Array): Promise<{reconciled: true; receipt: Receipt}>;
}
