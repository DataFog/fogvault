# fogvault-age

This is a narrowly supported FogVault backend fork of age 0.11.5.
Original upstream Rust sources and notices are retained. See README.md for upstream background.
The package metadata supports only FogVault's existing backend feature closure;
general upstream feature parity is not promised. Upstream development, benchmark
and example targets/dependencies and unused opt-in feature dependencies are omitted.
Those original targets remain in the retained upstream source archive in the
FogVault repository. This does not remove FogVault backup APIs or native default backup.

Retained declared features: default.
Unused upstream cfg branches remain in the unchanged Rust sources and cannot be
enabled as Cargo features of this fork. Original package licenses apply.
