// The event page/service worker owns no vault, passwords, keys or plaintext.
// Browser suspension/restart therefore starts with no recoverable authority.
const api = globalThis.browser || globalThis.chrome;
api.action.onClicked.addListener(() => { void api.tabs.create({url: api.runtime.getURL('vault.html')}); });
// Deliberately no content-script or external message bridge to vault operations.
