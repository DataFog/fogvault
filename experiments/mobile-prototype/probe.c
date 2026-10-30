#include "fogvault_probe.h"
#include "password_vectors.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static int failed = 0;
static void expect(int okay, const char *name) {
    printf("CASE %s %s\n", name, okay ? "PASS" : "FAIL");
    if (!okay) failed = 1;
}
static void wipe(void *memory, size_t length) {
    volatile unsigned char *bytes = (volatile unsigned char *)memory;
    while (length--) *bytes++ = 0;
}

/* Each generated vector is synthetic. Its expected bytes come from the shared
 * fixed JSON contract, independently of the Rust conversion under test. */
static void password_vectors(void) {
    unsigned char output[FV_PASSWORD_VECTOR_CAPACITY];
    size_t written = 99, checked = 0;
    int okay = 1;
    for (size_t i = 0; i < FV_PASSWORD_TEXT_COUNT; ++i) {
        const struct fv_password_text_vector *v = &fv_password_text_vectors[i];
        memset(output, 0x5a, sizeof(output));
        int32_t status = fv_probe_password_utf8(v->input, v->input_len,
                                               output, sizeof(output), &written);
        ++checked;
        int passed = status == FV_OK && written == v->expected_len &&
                     memcmp(output, v->expected, v->expected_len) == 0 &&
                     (written == sizeof(output) || output[written] == 0x5a);
        okay &= passed;
        printf("VECTOR password-utf8-golden-vectors %s %s\n", v->id, passed ? "PASS" : "FAIL");
        wipe(output, sizeof(output));
    }
    expect(okay, "password-utf8-golden-vectors");
    printf("COUNT password-utf8-golden-vectors %zu\n", checked);
    okay = 1;
    checked = 0;
    for (size_t i = 0; i < FV_PASSWORD_INVALID_UTF8_COUNT; ++i) {
        const struct fv_password_bytes *v = &fv_password_invalid_utf8_vectors[i];
        memset(output, 0x5a, sizeof(output));
        int32_t status = fv_probe_password_utf8(v->bytes, v->length,
                                               output, sizeof(output), &written);
        ++checked;
        int passed = status == FV_INVALID_INPUT && written == 0;
        for (size_t j = 0; j < sizeof(output); ++j) passed &= output[j] == 0x5a;
        okay &= passed;
        printf("VECTOR password-invalid-utf8-rejects-without-output %s %s\n", v->id, passed ? "PASS" : "FAIL");
    }
    expect(okay, "password-invalid-utf8-rejects-without-output");
    printf("COUNT password-invalid-utf8-rejects-without-output %zu\n", checked);
    memset(output, 0x5a, sizeof(output));
    const unsigned char one[] = {'x'};
    okay = fv_probe_password_utf8(NULL, 0, NULL, 0, &written) == FV_OK && written == 0;
    okay &= fv_probe_password_utf8(NULL, 1, output, sizeof(output), &written) == FV_ARGUMENT && written == 0;
    okay &= fv_probe_password_utf8(one, (size_t)-1, output, 0, &written) == FV_ARGUMENT && written == 0;
    okay &= fv_probe_password_utf8(NULL, 0, output, (size_t)-1, &written) == FV_ARGUMENT && written == 0;
    okay &= fv_probe_password_utf8(NULL, 0, NULL, 1, &written) == FV_ARGUMENT && written == 0;
    okay &= fv_probe_password_utf8(NULL, 0, NULL, 0, NULL) == FV_ARGUMENT;
    okay &= fv_probe_password_utf8(one, 1, output, 0, &written) == FV_BUFFER_TOO_SMALL && written == 0;
    for (size_t i = 0; i < sizeof(output); ++i) okay &= output[i] == 0x5a;
    expect(okay, "password-text-boundary-argument-and-buffer-errors");
    wipe(output, sizeof(output));
}

static int password_flow(const unsigned char *password, size_t length,
                         int check_embedded_nul, int *rejection_preserves_authority) {
    unsigned char payload[] = "SYNTHETIC-password-byte-payload";
    unsigned char token[16] = {0}, output[sizeof(payload)], converted[FV_PASSWORD_VECTOR_CAPACITY];
    size_t written = 0;
    uint64_t handle = 0;
    int okay = fv_probe_create(password, length, payload, sizeof(payload), &handle) == FV_OK && handle != 0;
    if (!okay) return 0;
    if (check_embedded_nul) {
        size_t prefix = 0;
        while (prefix < length && password[prefix] != 0) ++prefix;
        okay &= prefix < length &&
                fv_probe_unlock(handle, password, prefix, token) == FV_AUTHENTICATION;
    }
    okay &= fv_probe_unlock(handle, password, length, token) == FV_OK;
    okay &= fv_probe_read(handle, token, sizeof(token), output, sizeof(output), &written) == FV_OK &&
            written == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0;
    if (rejection_preserves_authority != NULL) {
        const struct fv_password_bytes *bad = &fv_password_invalid_utf8_vectors[0];
        memset(converted, 0x5a, sizeof(converted));
        *rejection_preserves_authority =
            fv_probe_password_utf8(bad->bytes, bad->length, converted, sizeof(converted), &written) == FV_INVALID_INPUT &&
            written == 0 && converted[0] == 0x5a &&
            fv_probe_read(handle, token, sizeof(token), output, sizeof(output), &written) == FV_OK &&
            written == sizeof(payload) && memcmp(output, payload, sizeof(payload)) == 0;
    }
    okay &= fv_probe_lock(handle) == FV_OK &&
            fv_probe_read(handle, token, sizeof(token), output, sizeof(output), &written) == FV_LOCKED && written == 0;
    okay &= fv_probe_release(handle) == FV_OK;
    wipe(payload, sizeof(payload)); wipe(token, sizeof(token)); wipe(output, sizeof(output));
    wipe(converted, sizeof(converted));
    return okay;
}

static void password_lifecycle(void) {
    const struct fv_password_text_vector *text = &fv_password_text_vectors[FV_PASSWORD_LIFECYCLE_INDEX];
    unsigned char password[FV_PASSWORD_VECTOR_CAPACITY];
    size_t written = 0;
    int preserves_authority = 0;
    int okay = fv_probe_password_utf8(text->input, text->input_len, password,
                                      sizeof(password), &written) == FV_OK;
    okay &= written == text->expected_len && memcmp(password, text->expected, written) == 0;
    okay &= password_flow(password, written, 1, &preserves_authority);
    expect(okay, "password-unicode-nul-create-unlock-read");
    int raw_okay = 1;
    size_t raw_checked = 0;
    for (size_t i = 0; i < FV_PASSWORD_RAW_COUNT; ++i) {
        const struct fv_password_bytes *raw = &fv_password_raw_vectors[i];
        int passed = password_flow(raw->bytes, raw->length, 0, NULL);
        ++raw_checked;
        raw_okay &= passed;
        printf("VECTOR password-raw-binary-create-unlock-read %s %s\n", raw->id, passed ? "PASS" : "FAIL");
    }
    expect(raw_okay, "password-raw-binary-create-unlock-read");
    printf("COUNT password-raw-binary-create-unlock-read %zu\n", raw_checked);
    expect(password_flow(NULL, 0, 0, NULL), "password-empty-create-unlock-read");
    expect(preserves_authority, "password-invalid-text-preserves-active-authority");
    wipe(password, sizeof(password));
}
int main(void) {
    unsigned char password[] = "SYNTHETIC-mobile-probe-only";
    unsigned char payload[] = "SYNTHETIC-opaque-payload";
    unsigned char first[16] = {0}, second[16] = {0}, output[128];
    size_t written = 99;
    uint64_t handle = 0;
    int32_t result = fv_probe_create(password, sizeof(password)-1, payload, sizeof(payload)-1, &handle);
    expect(result == FV_OK && handle != 0, "p2-create-with-caller-owned-inputs");
    if (result != FV_OK) return 1;
    memset(output, 0x5a, sizeof(output));
    expect(fv_probe_read(handle, first, sizeof(first), output, sizeof(output), &written) == FV_LOCKED && written == 0 && output[0] == 0x5a, "locked-read-rejects-without-output");
    expect(fv_probe_unlock(handle, password, sizeof(password)-1, first) == FV_OK, "p2-unlock");
    expect(fv_probe_read(handle, first, sizeof(first), output, 1, &written) == FV_BUFFER_TOO_SMALL && written == 0 && output[0] == 0x5a, "short-buffer-leaves-output-unchanged");
    expect(fv_probe_read(handle, first, sizeof(first), output, sizeof(output), &written) == FV_OK && written == sizeof(payload)-1 && memcmp(output,payload,written) == 0, "p2-read-byte-equality");
    wipe(output,sizeof(output));
    expect(fv_probe_unlock(handle, (const unsigned char *)"wrong", 5, second) == FV_AUTHENTICATION && memcmp(second,(unsigned char[16]){0},16)==0, "wrong-password-revokes-session");
    expect(fv_probe_read(handle, first, sizeof(first), output, sizeof(output), &written) == FV_LOCKED && written == 0, "old-session-after-failed-unlock-rejects");
    expect(fv_probe_unlock(handle,password,sizeof(password)-1,second)==FV_OK, "reunlock");
    expect(fv_probe_read(handle,first,sizeof(first),output,sizeof(output),&written)==FV_STALE_SESSION && written==0, "stale-session-after-reunlock-rejects");
    expect(fv_probe_read(handle,second,sizeof(second),NULL,0,&written)==FV_BUFFER_TOO_SMALL && written==0, "null-zero-capacity-is-short-buffer");
    expect(fv_probe_read(handle,second,sizeof(second),NULL,1,&written)==FV_ARGUMENT && written==0, "null-nonzero-output-rejects");
    expect(fv_probe_read(handle,NULL,16,output,sizeof(output),&written)==FV_ARGUMENT && written==0, "null-token-rejects");
    expect(fv_probe_read(handle,second,sizeof(second),output,(size_t)-1,&written)==FV_ARGUMENT && written==0, "overflow-capacity-rejects");
    expect(fv_probe_tamper_record(handle)==FV_OK && fv_probe_read(handle,second,sizeof(second),output,sizeof(output),&written)==FV_INTEGRITY && written==0, "tamper-rejects-before-plaintext-copy");
    expect(fv_probe_lock(handle)==FV_OK && fv_probe_read(handle,second,sizeof(second),output,sizeof(output),&written)==FV_LOCKED && written==0, "lock-revokes-session");
    expect(fv_probe_release(handle)==FV_OK, "release-live-handle");
    expect(fv_probe_lock(handle)==FV_INVALID_HANDLE && fv_probe_read(handle,second,sizeof(second),output,sizeof(output),&written)==FV_INVALID_HANDLE && written==0, "released-handle-rejects");
    expect(fv_probe_release(handle)==FV_INVALID_HANDLE, "double-release-rejects");
    password_vectors();
    password_lifecycle();
    wipe(password,sizeof(password));wipe(payload,sizeof(payload));wipe(output,sizeof(output));wipe(first,sizeof(first));wipe(second,sizeof(second));
    printf("RESULT %s\n", failed ? "FAIL" : "PASS");
    return failed;
}
