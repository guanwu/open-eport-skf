/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* Public API, device lifetime, and signature sequencing.
 *
 * This layer holds the three per-device facts that must not differ between
 * media: the parsed certificate cache, the local PIN authorization, and the
 * streaming hash. Media move bytes and interpret card status; every state
 * transition a caller can observe is decided here.
 */
#include "internal.h"

#include <stdlib.h>
#include <string.h>

#define EPORT_PCSC_PREFIX "[PCSC] "
#define EPORT_HID_PREFIX "[HID] "

typedef struct eport_enumeration {
    eportskf_device_list list;
    size_t capacity;
    int failed;
} eport_enumeration;

static char *eport_copy_string(const char *source)
{
    size_t length;
    char *copy;

    if (source == NULL) {
        return NULL;
    }
    length = strlen(source) + 1;
    copy = malloc(length);
    if (copy != NULL) {
        memcpy(copy, source, length);
    }
    return copy;
}

static eportskf_result eport_copy_identity(
    const eport_certificate *certificate,
    eportskf_identity *out_identity)
{
    memset(out_identity, 0, sizeof(*out_identity));
    out_identity->cert_id = eport_copy_string(certificate->cert_id);
    out_identity->device_id = eport_copy_string(certificate->device_id);
    if (out_identity->cert_id == NULL || out_identity->device_id == NULL) {
        eportskf_free_identity(out_identity);
        return EPORTSKF_FAILURE;
    }
    return EPORTSKF_SUCCESS;
}

/* Reads and parses the certificate once per handle. A failed read leaves the
   handle open and is retried by the next call, so a transient card error does
   not force the caller to reopen the device. */
static eportskf_result eport_load_certificate(eportskf_device *device)
{
    uint8_t der[EPORT_CERTIFICATE_CAPACITY];
    size_t length = 0;
    eport_certificate certificate;
    eportskf_result result;

    if (device->certificate_ready) {
        return EPORTSKF_SUCCESS;
    }
    memset(&certificate, 0, sizeof(certificate));
    result = device->operations->read_certificate(device->implementation, der, &length);
    if (result == EPORTSKF_DEVICE_UNAVAILABLE) {
        device->authorized = 0;
    }
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    result = eport_certificate_parse(der, length, &certificate);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    device->certificate = certificate;
    device->certificate_ready = 1;
    return EPORTSKF_SUCCESS;
}

const char *eportskf_result_description(eportskf_result result)
{
    switch (result) {
    case EPORTSKF_SUCCESS:
        return "Success";
    case EPORTSKF_UNUSABLE_ARGUMENT:
        return "Unusable argument";
    case EPORTSKF_DEVICE_UNAVAILABLE:
        return "Device unavailable";
    case EPORTSKF_PIN_REJECTED:
        return "PIN rejected";
    case EPORTSKF_VERIFICATION_REQUIRED:
        return "Verification required";
    case EPORTSKF_FAILURE:
    default:
        return "Failure";
    }
}

void eportskf_free_identity(eportskf_identity *identity)
{
    if (identity == NULL) {
        return;
    }
    free(identity->cert_id);
    free(identity->device_id);
    memset(identity, 0, sizeof(*identity));
}

void eportskf_free_device_list(eportskf_device_list *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    for (index = 0; index < list->count; ++index) {
        free(list->items[index].name);
        eportskf_free_identity(&list->items[index].identity);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

/* Visitor for both media enumerations. A candidate that cannot be opened or
   identified is skipped, so the list reports only devices that are readable
   right now; a nonzero result stops the enumeration. */
static eportskf_result eport_collect_device(const char *name, void *context)
{
    eport_enumeration *enumeration = context;
    eportskf_device *device = NULL;
    eportskf_device_info item;
    eportskf_device_info *items;
    size_t capacity;

    memset(&item, 0, sizeof(item));
    if (eportskf_open(name, &device) != EPORTSKF_SUCCESS) {
        return EPORTSKF_SUCCESS;
    }
    if (eportskf_read_identity(device, &item.identity) != EPORTSKF_SUCCESS) {
        (void)eportskf_close(device);
        return EPORTSKF_SUCCESS;
    }
    (void)eportskf_close(device);

    item.name = eport_copy_string(name);
    if (item.name == NULL) {
        eportskf_free_identity(&item.identity);
        enumeration->failed = 1;
        return EPORTSKF_FAILURE;
    }
    if (enumeration->list.count == enumeration->capacity) {
        capacity = enumeration->capacity == 0 ? 4 : enumeration->capacity * 2;
        if (capacity < enumeration->capacity || capacity > SIZE_MAX / sizeof(*items)) {
            free(item.name);
            eportskf_free_identity(&item.identity);
            enumeration->failed = 1;
            return EPORTSKF_FAILURE;
        }
        items = realloc(enumeration->list.items, capacity * sizeof(*items));
        if (items == NULL) {
            free(item.name);
            eportskf_free_identity(&item.identity);
            enumeration->failed = 1;
            return EPORTSKF_FAILURE;
        }
        enumeration->list.items = items;
        enumeration->capacity = capacity;
    }
    enumeration->list.items[enumeration->list.count++] = item;
    return EPORTSKF_SUCCESS;
}

/* PC/SC candidates come first, then HID. A failure while collecting aborts the
   whole enumeration rather than returning a partial list. */
eportskf_result eportskf_enumerate(eportskf_device_list *out_list)
{
    eport_enumeration enumeration;

    if (out_list == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    out_list->items = NULL;
    out_list->count = 0;
    memset(&enumeration, 0, sizeof(enumeration));
    (void)eport_pcsc_enumerate(eport_collect_device, &enumeration);
    if (!enumeration.failed) {
        (void)eport_hid_enumerate(eport_collect_device, &enumeration);
    }
    if (enumeration.failed) {
        eportskf_free_device_list(&enumeration.list);
        return EPORTSKF_FAILURE;
    }
    *out_list = enumeration.list;
    return EPORTSKF_SUCCESS;
}

/* The prefix selects the medium and is removed before the medium sees the
   name. An empty descriptor cannot name a device, so it is rejected here
   instead of reaching a platform layer. */
eportskf_result eportskf_open(const char *name, eportskf_device **out_device)
{
    if (out_device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    *out_device = NULL;
    if (name == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    if (strncmp(name, EPORT_PCSC_PREFIX, strlen(EPORT_PCSC_PREFIX)) == 0 && name[strlen(EPORT_PCSC_PREFIX)] != '\0') {
        return eport_pcsc_open(name + strlen(EPORT_PCSC_PREFIX), out_device);
    }
    if (strncmp(name, EPORT_HID_PREFIX, strlen(EPORT_HID_PREFIX)) == 0 && name[strlen(EPORT_HID_PREFIX)] != '\0') {
        return eport_hid_open(name + strlen(EPORT_HID_PREFIX), out_device);
    }
    return EPORTSKF_DEVICE_UNAVAILABLE;
}

/* Local state is cleared before the transport closes, so a transport error
   cannot leave an authorized handle behind. The handle itself is released on
   every path. */
eportskf_result eportskf_close(eportskf_device *device)
{
    eportskf_result result;

    if (device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    device->authorized = 0;
    device->signing = 0;
    result = device->operations->close(device->implementation);
    eport_certificate_free(&device->certificate);
    free(device);
    return result;
}

eportskf_result eportskf_read_identity(eportskf_device *device, eportskf_identity *out_identity)
{
    eportskf_result result;

    if (device == NULL || out_identity == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    memset(out_identity, 0, sizeof(*out_identity));
    result = eport_load_certificate(device);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    return eport_copy_identity(&device->certificate, out_identity);
}

eportskf_result eportskf_verify_pin(eportskf_device *device, const char *pin)
{
    size_t index;
    eportskf_result result;

    if (device == NULL || pin == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    for (index = 0; index < EPORTSKF_PIN_SIZE; ++index) {
        if (pin[index] == '\0') {
            return EPORTSKF_UNUSABLE_ARGUMENT;
        }
    }
    if (pin[EPORTSKF_PIN_SIZE] != '\0') {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    result = device->operations->verify_pin(device->implementation, (const uint8_t *)pin);
    if (result == EPORTSKF_SUCCESS) {
        device->authorized = 1;
    } else if (result == EPORTSKF_DEVICE_UNAVAILABLE) {
        device->authorized = 0;
    }
    return result;
}

/* SM2 hashes ZA, which needs the public point from the cached certificate, so
   a missing or unusable certificate fails the start; SHA1 needs no identity
   data. A failed start leaves the device idle and can be retried. */
eportskf_result eportskf_sign_start(eportskf_device *device)
{
    eportskf_result result;

    if (device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    if (device->signing) {
        return EPORTSKF_FAILURE;
    }
    if (device->medium == EPORT_MEDIUM_PCSC) {
        result = eport_load_certificate(device);
        if (result != EPORTSKF_SUCCESS) {
            return result;
        }
        if (!device->certificate.has_sm2_public_key) {
            return EPORTSKF_FAILURE;
        }
        eport_sm2_digest_init(&device->hash.sm3, device->certificate.sm2_public_key);
    } else {
        eport_sha1_init(&device->hash.sha1);
    }
    device->signing = 1;
    return EPORTSKF_SUCCESS;
}

eportskf_result eportskf_sign_update(eportskf_device *device, const void *data, size_t length)
{
    if (device == NULL || (data == NULL && length != 0)) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    if (!device->signing) {
        return EPORTSKF_FAILURE;
    }
    if (length == 0) {
        return EPORTSKF_SUCCESS;
    }
    if (device->medium == EPORT_MEDIUM_PCSC) {
        eport_sm3_update(&device->hash.sm3, data, length);
    } else {
        eport_sha1_update(&device->hash.sha1, data, length);
    }
    return EPORTSKF_SUCCESS;
}

/* The active signature is consumed before any check, so every return path
   leaves the device idle. The medium fixes the signature size, and the local
   copy keeps a medium that reports another size from overrunning the public
   buffer. */
eportskf_result eportskf_sign_finish(eportskf_device *device, eportskf_signature *out_signature)
{
    uint8_t digest[EPORT_SM3_DIGEST_SIZE];
    uint8_t signature[EPORTSKF_SIGNATURE_CAPACITY];
    size_t signature_length = 0;
    size_t expected_length;
    eportskf_result result;

    if (device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    if (!device->signing) {
        return EPORTSKF_FAILURE;
    }
    device->signing = 0;
    if (out_signature == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    memset(out_signature, 0, sizeof(*out_signature));
    out_signature->algorithm = device->medium == EPORT_MEDIUM_PCSC
        ? EPORTSKF_ALGORITHM_SM2_SM3
        : EPORTSKF_ALGORITHM_RSA_SHA1;
    if (!device->authorized) {
        return EPORTSKF_VERIFICATION_REQUIRED;
    }
    if (device->medium == EPORT_MEDIUM_PCSC) {
        expected_length = 64;
        eport_sm3_final(&device->hash.sm3, digest);
    } else {
        expected_length = 128;
        eport_sha1_final(&device->hash.sha1, digest);
    }
    result = device->operations->sign_digest(device->implementation, digest, signature, &signature_length);
    if (result == EPORTSKF_DEVICE_UNAVAILABLE || result == EPORTSKF_VERIFICATION_REQUIRED) {
        device->authorized = 0;
    }
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (signature_length != expected_length || signature_length > sizeof(signature)) {
        return EPORTSKF_FAILURE;
    }
    memcpy(out_signature->bytes, signature, signature_length);
    out_signature->length = signature_length;
    return EPORTSKF_SUCCESS;
}

eportskf_result eportskf_sign_abort(eportskf_device *device)
{
    if (device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    if (!device->signing) {
        return EPORTSKF_FAILURE;
    }
    device->signing = 0;
    return EPORTSKF_SUCCESS;
}

/* The one-shot operation is the streaming sequence with a single update, so
   both paths submit the same digest. A failure in the update abandons the
   state the start created. */
eportskf_result eportskf_sign(
    eportskf_device *device,
    const void *data,
    size_t length,
    eportskf_signature *out_signature)
{
    eportskf_result result;

    if (device == NULL || out_signature == NULL || (data == NULL && length != 0)) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    result = eportskf_sign_start(device);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    result = eportskf_sign_update(device, data, length);
    if (result != EPORTSKF_SUCCESS) {
        (void)eportskf_sign_abort(device);
        return result;
    }
    return eportskf_sign_finish(device, out_signature);
}
