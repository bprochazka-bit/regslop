/*
 * A minimal C smoke driver for the libreg C ABI. It proves the header is valid
 * C and the cdylib links and runs: create a hive, write a value, save, reload,
 * read it back. This is the C-driven half of the issue #106 acceptance bar;
 * the harness wires a fuller FFI backend for the cross-agent semantic check.
 *
 * Build (from libreg/):
 *   cargo build --release
 *   cc -I include tests/ffi/smoke.c -L target/release -llibreg -o /tmp/libreg_smoke
 *   LD_LIBRARY_PATH=target/release /tmp/libreg_smoke
 */

#include "libreg.h"
#include <stdio.h>
#include <string.h>

#define CHECK(call)                                                            \
    do {                                                                       \
        libreg_status _s = (call);                                             \
        if (_s != LIBREG_OK) {                                                 \
            fprintf(stderr, "%s -> %d: %s\n", #call, (int)_s,                   \
                    libreg_last_error());                                      \
            return 1;                                                          \
        }                                                                      \
    } while (0)

int main(void) {
    printf("libreg version: %s\n", libreg_version());

    const char *path = "/tmp/libreg_c_smoke.hive";
    libreg_hive_t h = 0;
    CHECK(libreg_hive_create(path, &h));
    CHECK(libreg_key_create(h, "Software\\Example"));

    uint32_t dword = 0x12345678u;
    CHECK(libreg_value_set(h, "Software\\Example", "Dword", 4 /* REG_DWORD */,
                           (const uint8_t *)&dword, sizeof dword));
    CHECK(libreg_hive_save(h));
    CHECK(libreg_hive_close(h));

    libreg_hive_t r = 0;
    CHECK(libreg_hive_load(path, &r));
    uint32_t type = 0;
    uint8_t *data = NULL;
    size_t len = 0;
    CHECK(libreg_value_get(r, "Software\\Example", "Dword", &type, &data, &len));
    if (type != 4 || len != sizeof dword || memcmp(data, &dword, len) != 0) {
        fprintf(stderr, "value did not round-trip\n");
        return 1;
    }
    libreg_free(data, len);
    CHECK(libreg_hive_close(r));

    printf("ok: value round-tripped through the C ABI\n");
    return 0;
}
