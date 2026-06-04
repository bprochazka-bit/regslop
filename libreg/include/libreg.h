/*
 * libreg.h: the stable C ABI for libreg, the cross-platform Windows Registry
 * hive library.
 *
 * This header is the committed surface of Layer 4 `api/` (issue #106). It is
 * governed by docs/ffi-abi.md (ratified in issue #107), which owns the error
 * model, the binary-native representation, versioning, and panic/ownership
 * rules. The concrete symbols, the handle type, and this header are defined by
 * the library agent; the spec agent appends them to docs/ffi-abi.md once the
 * cdylib lands (library supplies, spec appends).
 *
 * Conventions:
 *  - Every call returns a libreg_status; results come back through out
 *    parameters. The integer status is the contract; libreg_last_error()
 *    returns a human-readable detail for the last failing call on this thread.
 *  - Binary data and security descriptors cross as (pointer, length) of raw
 *    bytes, never base64. Integer value types (REG_DWORD/REG_QWORD) are the
 *    raw little-endian bytes of the value, with the REG_* code passed
 *    separately. The base64 and "QWORD as string" rules are HTTP/JSON wire
 *    artifacts and do NOT apply here (docs/ffi-abi.md section 2).
 *  - Buffers the library hands out (out_data, out_names, out_desc,
 *    out_problems) are owned by the caller and MUST be released with
 *    libreg_free(ptr, len), using the exact length the library reported.
 *  - Handles are opaque tokens created and destroyed only by this API. A
 *    handle is not thread-safe: do not use one handle from two threads at
 *    once. Distinct handles are independent.
 *  - Security descriptors are the raw binary self-relative form. libreg does
 *    not parse or emit SDDL; the SDDL/binary conversion is the consumer's job
 *    (ADR 0003), exactly as it is on the HTTP side.
 */

#ifndef LIBREG_H
#define LIBREG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Outcome codes. These map 1:1 to the CONTRACTS.md "Error Codes" table, in
 * that table's order, with success as 0 (docs/ffi-abi.md section 1). The
 * BAD_REQUEST (caller error) vs INTERNAL (library bug) split is preserved.
 */
typedef enum libreg_status {
    LIBREG_OK = 0,
    LIBREG_HIVE_NOT_FOUND = 1,
    LIBREG_HIVE_CORRUPT = 2,
    LIBREG_HANDLE_INVALID = 3,
    LIBREG_KEY_NOT_FOUND = 4,
    LIBREG_KEY_EXISTS = 5,
    LIBREG_VALUE_NOT_FOUND = 6,
    LIBREG_TYPE_MISMATCH = 7,
    LIBREG_ACCESS_DENIED = 8,
    LIBREG_LOG_CORRUPT = 9,
    LIBREG_KEY_HAS_CHILDREN = 10,
    LIBREG_BAD_REQUEST = 11,
    LIBREG_INTERNAL = 12
} libreg_status;

/* An opaque hive handle. Zero is never a valid handle. */
typedef uint64_t libreg_hive_t;

/* ---- Library-wide ---------------------------------------------------- */

/*
 * The backend id string (e.g. "libreg-0.1.0"), identical to the agent
 * handshake `backend` field, so a binding checks the C ABI version the same
 * way it checks /version over HTTP. The pointer is static; do not free it.
 */
const char *libreg_version(void);

/*
 * The detail string for this thread's most recent failing call. Never null
 * (empty before any error). Valid until the next libreg call on this thread.
 * Do not free it. Diagnostic only; the status code is the contract.
 */
const char *libreg_last_error(void);

/*
 * Release a (pointer, length) buffer the library handed out. `len` must be the
 * exact length the library reported alongside the pointer. A null pointer is a
 * no-op. Do not call on libreg_version()/libreg_last_error() results.
 */
void libreg_free(uint8_t *ptr, size_t len);

/* ---- Hive lifecycle -------------------------------------------------- */

/* Create an empty in-memory hive bound to `path`; nothing is written to disk
 * until libreg_hive_save(). On success *out_handle is a non-zero handle. */
libreg_status libreg_hive_create(const char *path, libreg_hive_t *out_handle);

/* Load the hive file at `path`, binding the handle to it for later saves. */
libreg_status libreg_hive_load(const char *path, libreg_hive_t *out_handle);

/* Write the hive back to the path it is bound to. */
libreg_status libreg_hive_save(libreg_hive_t handle);

/* Close the handle and free its hive. Reusing the handle is HANDLE_INVALID. */
libreg_status libreg_hive_close(libreg_hive_t handle);

/* ---- Keys ------------------------------------------------------------ */

/* Create the key at `path`, creating intermediates (RegCreateKeyEx
 * semantics). KEY_EXISTS when the leaf already exists. */
libreg_status libreg_key_create(libreg_hive_t handle, const char *path);

/* Delete the key at `path`. recursive == 0 rejects a key that still has
 * subkeys (KEY_HAS_CHILDREN); non-zero removes the whole subtree. The root
 * key cannot be deleted. */
libreg_status libreg_key_delete(libreg_hive_t handle, const char *path, int recursive);

/* List subkey names of `path` as a buffer of NUL-terminated UTF-8 strings
 * ("name0\0name1\0..."); *out_count is the number of names. Registry names
 * never contain an interior NUL. Release *out_names with libreg_free. */
libreg_status libreg_key_list_subkeys(libreg_hive_t handle, const char *path,
                                      uint8_t **out_names, size_t *out_len,
                                      size_t *out_count);

/* List value names of `path`, same encoding as libreg_key_list_subkeys. */
libreg_status libreg_key_list_values(libreg_hive_t handle, const char *path,
                                     uint8_t **out_names, size_t *out_len,
                                     size_t *out_count);

/* Report subkey and value counts of `path`. Either out pointer may be null. */
libreg_status libreg_key_info(libreg_hive_t handle, const char *path,
                              uint64_t *out_subkeys, uint64_t *out_values);

/* ---- Values ---------------------------------------------------------- */

/* Set value `name` on key `key_path` to `data`/`data_len` of REG_* type
 * `value_type`. Data is raw bytes (not base64); creates or replaces. The
 * default value is the empty name "". */
libreg_status libreg_value_set(libreg_hive_t handle, const char *key_path,
                               const char *name, uint32_t value_type,
                               const uint8_t *data, size_t data_len);

/* Get value `name` from key `key_path`. *out_type receives the REG_* code
 * (out_type may be null to skip it); *out_data/*out_len receive a fresh copy
 * of the raw bytes, released with libreg_free. VALUE_NOT_FOUND if absent. */
libreg_status libreg_value_get(libreg_hive_t handle, const char *key_path,
                               const char *name, uint32_t *out_type,
                               uint8_t **out_data, size_t *out_len);

/* Delete value `name` from key `key_path`. VALUE_NOT_FOUND if absent. */
libreg_status libreg_value_delete(libreg_hive_t handle, const char *key_path,
                                  const char *name);

/* ---- Security (binary self-relative descriptor) ---------------------- */

/* Get the binary security descriptor of key `path` into *out_desc/*out_len
 * (release with libreg_free). Binary, not SDDL: the consumer converts. */
libreg_status libreg_key_security_get(libreg_hive_t handle, const char *path,
                                      uint8_t **out_desc, size_t *out_len);

/* Set the binary security descriptor of key `path` to `desc`/`desc_len`. */
libreg_status libreg_key_security_set(libreg_hive_t handle, const char *path,
                                      const uint8_t *desc, size_t desc_len);

/* ---- Diagnostics ----------------------------------------------------- */

/* Validate the hive's structure. Problems come back as a NUL-separated name
 * buffer (release with libreg_free); *out_count == 0 means the hive is clean. */
libreg_status libreg_validate(libreg_hive_t handle, uint8_t **out_problems,
                              size_t *out_len, size_t *out_count);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LIBREG_H */
