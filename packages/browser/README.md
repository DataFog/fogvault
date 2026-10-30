# FogVault browser SDK

`@datafog/fogvault-browser` runs the shared Rust vault engine in an owned module
Worker. Its storage adapter uses IndexedDB. The caller supplies finite resource
and KDF policies; saved files cannot raise them.

This package uses version `0.1.0`. It does not claim independent cryptographic
approval or qualified physical-device budgets.
Original FogVault code uses MIT; bundled dependencies retain their own licenses.

## Build and install

From the repository root, with the WASM Rust target and matching
`wasm-bindgen 0.2.127` CLI installed:

```sh
npm ci --ignore-scripts --prefix packages/browser
npm run build --prefix packages/browser
npm test --prefix packages/browser
```

Run `npm pack` from `packages/browser/` to produce an installable tarball. Its
`dist/` contains the JavaScript entry, TypeScript declarations, Worker and WASM
assets. Serve/copy the complete asset directory from your own origin. No remote
code, cloud service or Codex installation is required by the SDK.

## Basic use

```js
import {FogVault, randomId, clearRecord} from '@datafog/fogvault-browser';

// Example policy for this application, not universal production defaults.
const vault = new FogVault({
  limits: {payload: 16 * 1024 * 1024, metadata: 64, records: 4096,
           staging: 32 * 1024 * 1024},
  kdfProfiles: [{memory_kib: 65536, passes: 3}],
  storageProfile: 'arraybuffer',
});
const created = await vault.create('my-vault', password, {recovery: true});
// created.recovery_key is secret owner-held material: export it safely, then wipe it.
const id = randomId();
await vault.save(id, new Uint8Array(), payload, {expectedRevision: 0n});
await vault.lock();
await vault.unlock(password);
const record = await vault.read(id);
try { consume(record.payload); } finally { clearRecord(record); }
await vault.close();
```

A save/delete intent captures the accepted head before asynchronous transport.
Supply `expectedHead` explicitly when acting on a previously read snapshot.
Expected revisions use `bigint`; zero inserts and positive values update. Reusing
a completed request ID with different contents fails. Latest identical retries
return the original receipt. There is no permanent historical request ledger.

Each owner permits one ordinary operation at a time. Conflicts from another tab
or owner require reopen/unlock against its new accepted state. Enumerate with
`beginRecords()` and bounded `recordPage(maximum)` calls; completion validates the
full committed inventory. The page result contains authenticated IDs/revisions,
not plaintext bodies.

## Passwords and lifecycle

Password strings use strict UTF-8 without trimming or Unicode normalization.
Unpaired surrogates reject. Raw passwords require attached, nonshared
`Uint8Array` buffers. The SDK snapshots inputs before waiting for the Worker;
caller-owned bytes are never erased. Owned adapter copies are cleared after
transport/use. Caller strings, returned plaintext and foreign/browser copies
remain outside Rust's erasure guarantees.

`lock()` immediately revokes the owner and terminates its Worker, including an
in-flight synchronous KDF. It does not promise that browser termination runs
WASM destructors. `unlock()` after locking creates a new Worker and reopens the
remembered database. `close()` permanently disposes the owner.

A lost reply after a submitted mutation is `FogVaultError` code `OutcomeUnknown`,
with its `requestId`. It is never reported as a definite abort. Reopen/unlock and
use `reconcileLatest(requestId)` for the current operation. Retain request IDs
outside a transient UI when operations must survive page/process loss. A later
operation can supersede that latest receipt.

## Owner recovery and protective replacement

`create(name, password, {recovery: true})` returns an 80-byte owner recovery kit
only after successful storage publication. `recover(kit, newPassword, requestId)`
works from a locked owner that has opened the target. It audits restricted
recovery authority, encrypts every record under fresh root/content keys and
atomically replaces the complete namespace. `replaceRecovery(oldPassword,
newPassword, requestId)` performs the same full protection from an unlocked
password session. Both return a new kit and `FreshRootAndContentKeys`.

An explicit positive `limits.staging` is required. It bounds retained staged
ciphertext/object bytes, not total process RSS, allocator overhead, browser
copies or the transient per-record crypto workspace. Staging refusal leaves the
old persistent graph unchanged and revokes the owner. A failed/replayed old kit
cannot obtain ordinary read authority.

These operations preserve IDs/revisions in the same vault. Old credentials and
kits can still read historical copies they already unlocked; current protection
does not retract those copies or previously returned plaintext.

## Backups and fresh restore

Backups use standard binary age/v1 X25519 encryption over FogVault's `FVEXP001`
payload. Supply an explicit `backupPolicy` with `headerBytes`, `stanzas`,
`ciphertextBytes`, `totalPlaintextBytes`, `records`, `schemaBytes`, `metadataBytes`,
`payloadBytes`, and `collectionBytes`. The last must admit at least
`ciphertextBytes + 2 * totalPlaintextBytes + 65536` data bytes. Runtime/allocator
and foreign copies need additional host headroom. This browser convenience path
collects bounded guarded plaintext records inside Rust. It does not claim
constant-memory backup/restore. Payload/record counts and target staging have
separate admission limits.

- `generateBackupIdentity()` explicitly exports an independent secret backup
  identity and public recipient. The secret is returned as caller-owned bytes.
- `exportBackup(recipient)` verifies records against one accepted snapshot and
  returns ciphertext, its digest and the 104-byte source header. Keep a trusted
  completed-export receipt independently from an untrusted archive/sidecar.
- `restoreBackup(name, ciphertext, identity, newPassword, approval, requestId)`
  accepts only a fresh target. Approval is either `{kind: 'trusted-receipt',
  sourceHeader, ciphertextSha256}` or the explicit
  `{kind: 'owner-accepted-unverified', sourceHeader}`. The latter never claims
  verified source origin.

Restore checks the complete encrypted stream, payload framing, source identity,
origin policy and encrypted-stage finality before opening the destination. No
plaintext records are exposed before those checks. A private fresh Rust engine
then encrypts a new graph and one IndexedDB transaction installs the entire
namespace. Existing destinations are never overwritten. This opaque-record
adapter rejects nonempty application schema fields rather than discarding them.

A restore creates a new vault identity and starts record revisions at one. Its
source header retains the exported snapshot identity; it is not the old CAS
namespace. The import request is bound into the authenticated target head so a
lost reply can be reconciled after reopening with the new password. Protective
same-vault recovery has different semantics and preserves record revisions.

## Websites and extensions

```sh
node packages/browser/scripts/build-examples.mjs chrome
node packages/browser/scripts/build-examples.mjs firefox
```

Serve `examples/website/` over a secure origin or localhost. Load the generated
`example-build/chrome/` unpacked, or install `example-build/firefox/` temporarily
with Firefox development tooling. These separate manifests match Chrome's MV3
service worker and Firefox's background event-page model.

The extension vault owner lives in a privileged extension page. The background
context only opens that page and holds no keys/plaintext, so suspension/restart
does not restore authority. There is no content-script/external decryption
message bridge. Closing/hiding the example page revokes the owner. Integrations
needing a different lifetime must choose and test that owner explicitly.

Authoritative background APIs: [Chrome service workers](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/basics),
[Firefox background contexts](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background).

## Device providers and access changes

The host can explicitly admit `password-or-device` and `password-and-device`,
finite descriptor/slot/provider-blob limits, and registered providers. Every
provider registration includes a stable 16-byte provider/key identity, an explicit
`NonExportableOperation` capability, and asynchronous `wrapSeed` / `unwrapSeed`
callbacks. These callbacks receive the Core-generated vault/epoch/slot context,
authenticated context bytes and an independent slot seed or provider blob. They
never receive the vault root/content keys. Return a nonshared attached
`Uint8Array`; the SDK takes ownership of and clears callback results.

Callbacks receive an `AbortSignal`. Locking cancels the request and late replies
cannot restore authority. Provider job ID, phase, fixed seed width and host blob
limits are checked before Rust copies provider-result bytes. The host is
responsible for qualifying its actual provider and its identity/device-binding
claims. The SDK does not label a software WebCrypto key as hardware-backed.
Synthetic test providers establish API/lifecycle behavior only.

Use `unlockDevice(slotId, password?)` for device access. The AND profile requires
the password and selected device. `changePasswordWithDevice` and
`upgradeKdfWithDevice` preserve existing device slots, recovery kits and content
keys. `enrollDevice(source, newIdentity)` adds one slot while preserving existing
slots and the recovery kit; an OR profile can authenticate by password when an
old device is offline.

`configureAccess(source, target)` initially installs an access graph. Existing
routes require the explicit `maintainAccess` operation; it returns `Preserved`
and requires an intentional target graph/recovery choice. `protectAccess`, named
`replaceDevice`, and `recoverAccess` encrypt all records under fresh root/content
keys and atomically publish the replacement. Every target explicitly chooses its
password, profile, devices and recovery route. Named lost-device replacement
rejects any target that retains a removed provider identity. `recoverAccess`
works with restricted owner-recovery authority and an explicit target graph.
Portable `recover` / `replaceRecovery` conveniences reject device-profile sources
so a device-backed graph cannot silently become password-only.

## Capabilities and support limits

`capabilities()` reports the admitted profile. Password access, guarded
password/KDF maintenance, authenticated CRUD/enumeration, optional owner recovery
and admitted backups/fresh restore are implemented. The device profiles and their
explicit host-provider boundary are described below. Unsupported capabilities
fail explicitly. A device-only request never selects password fallback.

This offline browser adapter is **unanchored**. It detects missing/changed
objects relative to an authenticated accepted head. Detecting replacement of the
entire vault with an older valid copy requires separately trusted state. IndexedDB
completion is the publication boundary with a strict durability hint; power-cut,
eviction/persistence and device-specific budgets require their own qualification.

Actual SDK acceptance is at `test/browser.html` and resolves
`window.fogvaultSdkDone`. It exercises the packaged Worker/WASM/IndexedDB API,
including credential changes, recovery, reply loss and backup finality. The
compatibility harness under `experiments/browser-prototype/` uses the same Rust
binding and storage/runtime source with diagnostics enabled only there.

The privileged host remains a trust boundary: WASM and IndexedDB do not isolate
keys from a compromised application origin or extension page. Protect script
loading, origin permissions and any application message bridges accordingly.
