#ifndef FOGVAULT_DISPOSABLE_PROBE_H
#define FOGVAULT_DISPOSABLE_PROBE_H
#include <stddef.h>
#include <stdint.h>
/* Disposable single-record in-memory P2 codec probe; NOT a supported SDK/storage adapter.
 * Non-null pointers must be accessible/aligned for the declared length, and remain
 * alive for the call. Callers must not race buffers. Every writable output,
 * including written, must be disjoint from all inputs and other outputs.
 * NULL with zero byte length is permitted for ordinary byte inputs/output capacity.
 * Input secrets and returned plaintext remain caller owned: clear them explicitly.
 * Registry handle IDs are never reused; released IDs and double release reject.
 * Registered-handle calls are synchronous/registry serialized; dispatch off UI.
 * Creation performs crypto before registry insertion; no global KDF admission.
 * Rust unwinds are contained as FV_FAILURE; allocation abort cannot be recovered.
 */
enum { FV_OK=0, FV_ARGUMENT=1, FV_AUTHENTICATION=2, FV_LOCKED=3,
       FV_STALE_SESSION=4, FV_BUFFER_TOO_SMALL=5, FV_INTEGRITY=6,
       FV_INVALID_HANDLE=7, FV_FAILURE=8, FV_INVALID_INPUT=9 };
/* Strict UTF-8 text-password conversion: copy exact Unicode scalar encoding.
 * No normalization, trimming, case folding, NUL termination or replacement.
 * Empty text and embedded NUL are valid. Invalid UTF-8 returns FV_INVALID_INPUT.
 * written is cleared first; output stays unchanged on every rejection.
 * Raw-byte create/unlock below accept arbitrary bytes independently of this helper.
 */
int32_t fv_probe_password_utf8(const uint8_t *, size_t, uint8_t *, size_t, size_t *);
int32_t fv_probe_create(const uint8_t *, size_t, const uint8_t *, size_t, uint64_t *);
int32_t fv_probe_unlock(uint64_t, const uint8_t *, size_t, uint8_t * /*16 bytes*/);
int32_t fv_probe_read(uint64_t, const uint8_t *, size_t, uint8_t *, size_t, size_t *);
int32_t fv_probe_lock(uint64_t);
int32_t fv_probe_release(uint64_t);
int32_t fv_probe_tamper_record(uint64_t); /* experiment-only fault injection */
#endif
