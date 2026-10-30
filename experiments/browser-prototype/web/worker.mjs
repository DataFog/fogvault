// Diagnostic harness uses exactly the maintained browser transaction runtime.
import init, * as bindings from '../pkg/fogvault_browser_feasibility.js';
import {installWorker} from '../../../packages/browser/src/worker-runtime.mjs';
await init();
installWorker(bindings, {
  storageProfile: new URL(import.meta.url).searchParams.get('storage') || 'blob',
  limits: {payload: 16 * 1024 * 1024, metadata: 32, records: 4096},
  diagnostics: true,
});
