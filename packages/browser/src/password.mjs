// Candidate text contract: exact Unicode scalars encoded as UTF-8. No trimming,
// normalization, case folding, BOM insertion or replacement of invalid UTF-16.
const passwordFields = {
  create: ['password'], unlock: ['password'],
  recover: ['recovery_key', 'new_password'], protective_replace: ['password', 'new_password'],
  restore_backup: ['identity', 'new_password'],
  access_change: ['new_password'], credential_access: ['password'],
  change_password: ['password', 'new_password'],
  prepare_password_change: ['password', 'new_password'],
  upgrade_kdf: ['password'], prepare_kdf_upgrade: ['password'],
};
function invalid(message) { const error = Error(message); error.code = 'InvalidInput'; return error; }

export function passwordTextToBytes(text) {
  if (typeof text !== 'string') throw invalid('password text must be a string');
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw invalid('password contains unpaired UTF-16 surrogate');
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw invalid('password contains unpaired UTF-16 surrogate');
    }
  }
  return new TextEncoder().encode(text);
}

export function passwordTextArguments(action, args) {
  const fields = passwordFields[action];
  if (!fields) throw invalid('operation does not take password text');
  const result = {...args}, owned = [];
  try {
    for (const field of fields) { result[field] = passwordTextToBytes(args[field]); owned.push(result[field]); }
    return result;
  } catch (error) { for (const bytes of owned) bytes.fill(0); throw error; }
}

export function validatePasswordBytes(action, args) {
  if ((action === 'unlock_device' || action === 'access_change') && args.password !== undefined && args.password !== null && !ordinaryPasswordBytes(args.password)) throw invalid('device password bytes required');
  if (action === 'credential_access' && args.kind === 'password' && !ordinaryPasswordBytes(args.new_password)) throw invalid('new password bytes required');
  if (action === 'access_change' && args.mode === 'recovery' && !ordinaryPasswordBytes(args.recovery_key)) throw invalid('recovery key bytes required');
  for (const field of passwordFields[action] || []) {
    if (!ordinaryPasswordBytes(args[field])) throw invalid('password bytes require Uint8Array with attached nonshared ArrayBuffer');
  }
}

function ordinaryPasswordBytes(value) {
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer)) return false;
  try { new Uint8Array(value.buffer, 0, 0); return true; } catch { return false; }
}

// Only call for arrays owned by this adapter/Worker; caller strings and foreign
// copies cannot be erased by the vault. Borrowed buffers must stay stable in use.
export function wipePasswordArguments(action, args) {
  if (['unlock_device', 'access_change', 'credential_access'].includes(action)) for (const key of ['password', 'new_password', 'recovery_key']) if (ordinaryPasswordBytes(args[key])) args[key].fill(0);
  for (const field of passwordFields[action] || []) if (ordinaryPasswordBytes(args[field])) args[field].fill(0);
}
