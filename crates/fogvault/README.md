# Portable FogVault candidate core

One Rust `Engine` owns keys, sessions, authenticated record/index checks, bounded
audits, mutation preparation, credential changes and uncertain-operation outcomes.
Normal creation selects credential grammar 3, content format 3 and root epoch
zero. Native, browser and mobile experiments use the same engine. Its default
API exposes no root keys or construction modules and has no DataFog, storage or
language binding dependency.

This unpublished `0.0.0` crate (`publish = false`) is an experimental engineering
baseline. Maintained packaging is in progress. APIs and saved bytes remain
provisional; no production support, permanent compatibility or security approval
is claimed.

## Host responsibilities

- Creation publishes the descriptor/head atomically before session activation.
- Unlock audits one coherent snapshot before publishing session authority.
- Reads verify accepted-head-bound membership and the selected encrypted record.
- Writes prepare encryption outside the storage transaction, then compare and
  publish the exact planned record/index/head changes atomically.
- Completion, known abort and unknown outcome are different states. Unknown
  publication blocks ordinary use until the exact operation can be reconciled.
- Lock revokes keys, session capabilities, drafts and pending audit authority.
  Hosts also fence queued work and stale callbacks. Already-returned plaintext
  and foreign-language copies remain the caller's responsibility.

These are contracts the adapter must implement. Calling a completion method does
not prove disk durability or make a host's control state independent of its vault
storage. The native SQLite and browser IndexedDB experiments exercise their
scoped transaction contracts. The mobile probe has in-memory storage only.

Ordinary credential maintenance intentionally rewraps unchanged root/content
keys. Named protective device/recovery replacement creates fresh root/content
keys. Generic route removal cannot silently select unchanged-key maintenance.
The core protective planner exists; a supported native bulk publication adapter
is still work. Neither operation retracts copied plaintext or historical
snapshots that an old credential can already decrypt.

The crate uses `std`. Portable refers to the exercised native/WASM/mobile targets,
not `no_std` or universal platform qualification. The `web` feature selects the
JavaScript entropy backend. The nondefault `experimental-codecs` feature exposes
diagnostic fixture/measurement helpers for the disposable harness; it is outside
the proposed maintained public surface.

## Check locally

From the repository root:

```sh
cargo test --locked --manifest-path crates/fogvault/Cargo.toml --no-default-features
python3 scripts/bootstrap-reference-db.py
CARGO_PROFILE_TEST_OPT_LEVEL=2 python3 -u scripts/verify-vault.py --with-feasibility
```

Core tests read the repository's synthetic `conformance/` fixtures. The full
profile also requires the pinned audit/interoperability inputs and installed
browser/mobile toolchains described in the root README. It retains exact
published DataFog Core `=0.5.0-beta.3` as a test consumer; DataFog does not become a
runtime dependency. Missing required tooling cannot count as a passing stage.

DataFog Core `0.5.0-beta.3` remains the minimum integration baseline. The exact
test pin preserves that coverage; it does not impose a runtime dependency or an
upper version limit. A separate v1 integration will be tested before claiming
v1 compatibility.

FogVault's original code is licensed under the [MIT License](../../LICENSE).
Third-party material retains its own terms and notices.
