import {FogVault, clearRecord} from './sdk/client.mjs';

// Example policy, not a universal minimum/maximum for production hosts.
const vault = new FogVault({limits: {payload: 16 * 1024 * 1024, metadata: 64, records: 4096},
  kdfProfiles: [{memory_kib: 65536, passes: 3}], storageProfile: 'arraybuffer'});
const id = new Uint8Array(16).fill(1), name = 'fogvault-extension-example';
const status = document.querySelector('#status'), password = document.querySelector('#password');
const execute = task => async () => { try { await task(); } catch (error) { status.textContent = `${error.code || 'Error'}: ${error.message}`; } finally { password.value = ''; } };
document.querySelector('#create').onclick = execute(async () => {
  await vault.create(name, password.value);
  await vault.save(id, new Uint8Array(), new TextEncoder().encode('SYNTHETIC extension example'), {expectedRevision: 0n});
  await vault.lock(); status.textContent = 'Saved encrypted record and locked.';
});
document.querySelector('#read').onclick = execute(async () => {
  await vault.open(name); await vault.unlock(password.value);
  const record = await vault.read(id);
  try { status.textContent = new TextDecoder().decode(record.payload); } finally { clearRecord(record); }
});
document.querySelector('#lock').onclick = execute(async () => { await vault.lock(); status.textContent = 'Locked'; });
// Backgrounding is a host policy choice. This example revokes on page hiding.
addEventListener('pagehide', () => { void vault.close(); });
document.addEventListener('visibilitychange', () => { if (document.hidden) void vault.lock(); });
