import init, * as bindings from './wasm/fogvault_wasm.js';
import {configuration} from './configuration.mjs';
import {installWorker} from './worker-runtime.mjs';

// This dedicated Worker is owned by one SDK instance. It accepts configuration
// only once and never enables the compatibility harness's diagnostics.
let initializing = false;
self.onmessage = async ({data}) => {
  if (initializing || data?.action !== 'initialize' || typeof data.channel !== 'string' || !/^[a-f0-9]{32}$/.test(data.channel)) return;
  initializing = true;
  try {
    const policy = configuration(data.configuration);
    await init();
    bindings.validate_kdf_policy(policy.kdfProfiles);
    installWorker(bindings, {...policy, channel: data.channel, diagnostics: false});
  } catch (error) {
    self.postMessage({channel: data.channel, initializationFailed: true, code: error?.code || 'UnsupportedCapability', error: String(error)});
    self.close();
  }
};
