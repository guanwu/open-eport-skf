/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* Public interface to the ePort smart card and USB token library.
 *
 * A device is either a PC/SC smart card, which produces SM2 signatures over
 * SM3, or a USB HID token, which produces RSA-1024 signatures over SHA1; the
 * medium is selected by the device-name prefix. Every operation reports one
 * eportskf_result value, and a handle holds no state the caller has to
 * inspect: results and outputs describe everything that happened.
 */
#ifndef EPORTSKF_H
#define EPORTSKF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#  if defined(EPORTSKF_STATIC)
#    define EPORTSKF_API
#  elif defined(EPORTSKF_BUILDING_LIBRARY)
#    define EPORTSKF_API __declspec(dllexport)
#  else
#    define EPORTSKF_API __declspec(dllimport)
#  endif
#else
#  define EPORTSKF_API __attribute__((visibility("default")))
#endif

/* Eight PIN bytes, which every medium treats as one fixed-size block. */
#define EPORTSKF_PIN_SIZE 8

/* Room for either signature: 64 SM2 bytes or 128 RSA bytes. */
#define EPORTSKF_SIGNATURE_CAPACITY 128

/* Values are fixed by the C ABI, so a stored result keeps its meaning. */
typedef enum eportskf_result {
    EPORTSKF_SUCCESS = 0,
    EPORTSKF_UNUSABLE_ARGUMENT = 1,
    EPORTSKF_DEVICE_UNAVAILABLE = 2,
    EPORTSKF_PIN_REJECTED = 3,
    EPORTSKF_VERIFICATION_REQUIRED = 4,
    EPORTSKF_FAILURE = 5
} eportskf_result;

/* The medium decides the algorithm; a caller never selects one. */
typedef enum eportskf_algorithm {
    EPORTSKF_ALGORITHM_NONE = 0,
    EPORTSKF_ALGORITHM_SM2_SM3 = 1,
    EPORTSKF_ALGORITHM_RSA_SHA1 = 2
} eportskf_algorithm;

/* One device identity. Both strings are library-owned and NUL-terminated;
   device_id is empty when the certificate carries no device extension. */
typedef struct eportskf_identity {
    char *cert_id;
    char *device_id;
} eportskf_identity;

/* One enumerable device: a name that eportskf_open accepts, and the identity
   that was read from the device during enumeration. */
typedef struct eportskf_device_info {
    char *name;
    eportskf_identity identity;
} eportskf_device_info;

/* A caller-owned list of library-allocated entries. Release every entry at
   once with eportskf_free_device_list. */
typedef struct eportskf_device_list {
    eportskf_device_info *items;
    size_t count;
} eportskf_device_list;

/* A finished signature; only the first length bytes of bytes are meaningful. */
typedef struct eportskf_signature {
    eportskf_algorithm algorithm;
    size_t length;
    uint8_t bytes[EPORTSKF_SIGNATURE_CAPACITY];
} eportskf_signature;

/* One open device with its own transport, certificate cache, and PIN
   authorization. Handles are independent, and the caller serializes the calls
   it makes on a single handle. */
typedef struct eportskf_device eportskf_device;

/* Returns the fixed English description of result. The text is part of the
   interface and is the same in the library and the command-line tool. */
EPORTSKF_API const char *eportskf_result_description(eportskf_result result);

/* Enumerates every readable device. Device names are UTF-8; identity fields
   are NUL-free ASCII. All strings are library-owned. A candidate that cannot
   be opened or identified is omitted, so an empty list is a success. Release
   the list with eportskf_free_device_list. */
EPORTSKF_API eportskf_result eportskf_enumerate(eportskf_device_list *out_list);
EPORTSKF_API void eportskf_free_device_list(eportskf_device_list *list);

/* Opens a name produced by eportskf_enumerate. A null name is unusable; an
   unknown prefix or an empty descriptor means the device is unavailable. */
EPORTSKF_API eportskf_result eportskf_open(const char *name, eportskf_device **out_device);

/* Releases the handle and abandons an unfinished signature. The handle is
   invalid afterwards; a transport error is reported after local cleanup. */
EPORTSKF_API eportskf_result eportskf_close(eportskf_device *device);

/* Returns a fresh copy of the certificate identity. A successful parse is
   cached, so a failed read can be retried on the same handle. */
EPORTSKF_API eportskf_result eportskf_read_identity(eportskf_device *device, eportskf_identity *out_identity);
EPORTSKF_API void eportskf_free_identity(eportskf_identity *identity);

/* pin points to exactly eight bytes followed by a terminating NUL. Success
   authorizes signing on this handle until close, transport loss, reset, or a
   6982 signing response. */
EPORTSKF_API eportskf_result eportskf_verify_pin(eportskf_device *device, const char *pin);

/* Signs data in one call: start, a single update, and finish. */
EPORTSKF_API eportskf_result eportskf_sign(
    eportskf_device *device,
    const void *data,
    size_t length,
    eportskf_signature *out_signature);

/* One device has at most one active streaming signature, and the medium
   decides the digest: SM3 seeded with ZA for SM2, plain SHA1 for RSA. finish
   and abort both consume the active signature, so start is required again for
   the next message. An empty update is valid, including a null pointer with
   zero length. finish reports EPORTSKF_VERIFICATION_REQUIRED without a
   signature when no PIN has been verified since authorization was last
   cleared. */
EPORTSKF_API eportskf_result eportskf_sign_start(eportskf_device *device);
EPORTSKF_API eportskf_result eportskf_sign_update(eportskf_device *device, const void *data, size_t length);
EPORTSKF_API eportskf_result eportskf_sign_finish(eportskf_device *device, eportskf_signature *out_signature);
EPORTSKF_API eportskf_result eportskf_sign_abort(eportskf_device *device);

#ifdef __cplusplus
}
#endif

#endif
