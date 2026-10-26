/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* ePort token application over USB HID.
 *
 * The token does not take APDUs directly. Each direction is a framed stream
 * carried in eight-byte reports: output streams are split into seven-byte
 * payloads and zero-padded, and an input stream starts with one declared
 * length byte followed by that many bytes, with any report padding ignored.
 * A session also has to perform the wake-up, information, and transport
 * unlock exchanges before the certificate file can be selected and read.
 */
#include "hid.h"

#include <stdlib.h>
#include <string.h>

#define EPORT_HID_APDU_CAPACITY (5 + EPORT_SHA1_DIGEST_SIZE)
#define EPORT_HID_RESPONSE_CAPACITY 255
#define EPORT_HID_CERTIFICATE_CHUNK 128

typedef struct eport_hid_device {
    eport_hid_platform_device *platform;
} eport_hid_device;

/* Every report carries seven stream bytes behind the report-ID byte, and the
   final report is zero-padded by its initializer. */
static eportskf_result eport_hid_write_stream(
    eport_hid_device *device,
    const uint8_t *stream,
    size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        uint8_t report[EPORT_HID_REPORT_SIZE] = {0};
        size_t chunk = length - offset;
        eportskf_result result;

        if (chunk > EPORT_HID_REPORT_SIZE - 1) {
            chunk = EPORT_HID_REPORT_SIZE - 1;
        }
        memcpy(report + 1, stream + offset, chunk);
        result = eport_hid_platform_write(device->platform, report);
        if (result != EPORTSKF_SUCCESS) {
            return result;
        }
        offset += chunk;
    }
    return EPORTSKF_SUCCESS;
}

/* The first report holds the report ID, the declared length, and the first
   payload bytes; later reports contribute payload from byte one. Bytes beyond
   the declared length are report padding and are ignored, and the declared
   length includes the two status bytes. */
static eportskf_result eport_hid_read_response(
    eport_hid_device *device,
    uint8_t response[EPORT_HID_RESPONSE_CAPACITY],
    size_t *response_length,
    uint16_t *status)
{
    uint8_t report[EPORT_HID_REPORT_SIZE];
    size_t declared_length;
    size_t received = 0;
    eportskf_result result = eport_hid_platform_read(device->platform, report);

    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (report[0] != 0) {
        return EPORTSKF_FAILURE;
    }

    declared_length = report[1];
    if (declared_length < 2) {
        return EPORTSKF_FAILURE;
    }

    while (received < declared_length) {
        size_t chunk_offset = received == 0 ? 2 : 1;
        size_t chunk_capacity = EPORT_HID_REPORT_SIZE - chunk_offset;
        size_t chunk = declared_length - received;

        if (received != 0) {
            result = eport_hid_platform_read(device->platform, report);
            if (result != EPORTSKF_SUCCESS) {
                return result;
            }
            if (report[0] != 0) {
                return EPORTSKF_FAILURE;
            }
        }
        if (chunk > chunk_capacity) {
            chunk = chunk_capacity;
        }
        memcpy(response + received, report + chunk_offset, chunk);
        received += chunk;
    }

    *response_length = declared_length - 2;
    *status = (uint16_t)((uint16_t)response[declared_length - 2] << 8)
        | response[declared_length - 1];
    return EPORTSKF_SUCCESS;
}

static eportskf_result eport_hid_exchange(
    eport_hid_device *device,
    const uint8_t *stream,
    size_t stream_length,
    uint8_t response[EPORT_HID_RESPONSE_CAPACITY],
    size_t *response_length,
    uint16_t *status)
{
    eportskf_result result = eport_hid_write_stream(device, stream, stream_length);

    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    return eport_hid_read_response(device, response, response_length, status);
}

/* A command stream is 0x02, a two-byte big-endian APDU length, then the APDU
   itself. The buffer bounds the longest command the token accepts. */
static eportskf_result eport_hid_command(
    eport_hid_device *device,
    const uint8_t *apdu,
    size_t apdu_length,
    uint8_t response[EPORT_HID_RESPONSE_CAPACITY],
    size_t *response_length,
    uint16_t *status)
{
    uint8_t stream[3 + EPORT_HID_APDU_CAPACITY];

    if (apdu_length > EPORT_HID_APDU_CAPACITY) {
        return EPORTSKF_FAILURE;
    }
    stream[0] = 0x02;
    stream[1] = (uint8_t)(apdu_length >> 8);
    stream[2] = (uint8_t)apdu_length;
    memcpy(stream + 3, apdu, apdu_length);
    return eport_hid_exchange(device, stream, apdu_length + 3, response, response_length, status);
}

/* Opens the token: the two session streams use prefix 0x01 and carry their own
   length, so they bypass eport_hid_command. The transport PIN is fixed by the
   product and is unrelated to the user PIN; a rejected unlock makes the token
   unavailable. The certificate file is selected once and stays selected for
   the session. */
static eportskf_result eport_hid_initialize(eport_hid_device *device)
{
    static const uint8_t session_streams[][5] = {
        {0x01, 0x00, 0x02, 0x10, 0x00},
        {0x01, 0x00, 0x02, 0x20, 0x00}
    };
    static const uint8_t unlock[] = {
        0x00, 0x20, 0x00, 0x8a, 0x08, '1', '3', '5', '7', '2', '4', '6', '8'
    };
    static const uint8_t select_certificate[] = {0x00, 0xa4, 0x00, 0x00, 0x02, 0x10, 0x07};
    uint8_t response[EPORT_HID_RESPONSE_CAPACITY];
    size_t response_length = 0;
    uint16_t status = 0;
    size_t index;
    eportskf_result result;

    for (index = 0; index < sizeof(session_streams) / sizeof(session_streams[0]); ++index) {
        result = eport_hid_exchange(
            device,
            session_streams[index],
            sizeof(session_streams[index]),
            response,
            &response_length,
            &status);
        if (result != EPORTSKF_SUCCESS) {
            return result;
        }
        if (status != 0x9000) {
            return EPORTSKF_FAILURE;
        }
    }

    result = eport_hid_command(device, unlock, sizeof(unlock), response, &response_length, &status);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (status != 0x9000) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    if (response_length != 0) {
        return EPORTSKF_FAILURE;
    }

    result = eport_hid_command(
        device,
        select_certificate,
        sizeof(select_certificate),
        response,
        &response_length,
        &status);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (status != 0x9000 || response_length != 0) {
        return EPORTSKF_FAILURE;
    }
    return EPORTSKF_SUCCESS;
}

/* The header read returns only the four DER header bytes; the declared content
   length is validated before any data is requested. Data is then read from
   offset zero in chunks the token accepts, and each chunk must arrive whole. */
static eportskf_result eport_hid_read_certificate(
    void *implementation,
    uint8_t *der,
    size_t *length)
{
    static const uint8_t read_header[] = {0x00, 0xb0, 0x00, 0x00, 0x04};
    eport_hid_device *device = implementation;
    uint8_t response[EPORT_HID_RESPONSE_CAPACITY];
    size_t response_length = 0;
    uint16_t status = 0;
    size_t certificate_length;
    size_t offset = 0;
    eportskf_result result;

    if (device == NULL || der == NULL || length == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    *length = 0;

    result = eport_hid_command(device, read_header, sizeof(read_header), response, &response_length, &status);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (status != 0x9000 || response_length != 4 || response[0] != 0x30 || response[1] != 0x82) {
        return EPORTSKF_FAILURE;
    }

    certificate_length = ((size_t)response[2] << 8 | response[3]) + 4;
    if (certificate_length <= 4 || certificate_length > EPORT_CERTIFICATE_CAPACITY) {
        return EPORTSKF_FAILURE;
    }

    while (offset < certificate_length) {
        uint8_t read_chunk[] = {
            0x00,
            0xb0,
            (uint8_t)(offset >> 8),
            (uint8_t)offset,
            0
        };
        size_t chunk = certificate_length - offset;

        if (chunk > EPORT_HID_CERTIFICATE_CHUNK) {
            chunk = EPORT_HID_CERTIFICATE_CHUNK;
        }
        read_chunk[4] = (uint8_t)chunk;
        result = eport_hid_command(device, read_chunk, sizeof(read_chunk), response, &response_length, &status);
        if (result != EPORTSKF_SUCCESS) {
            return result;
        }
        if (status != 0x9000 || response_length != chunk) {
            return EPORTSKF_FAILURE;
        }
        memcpy(der + offset, response, chunk);
        offset += chunk;
    }

    *length = certificate_length;
    return EPORTSKF_SUCCESS;
}

/* No challenge and no encryption: the token compares the eight PIN bytes
   directly, unlike the card, which needs the encrypted block. */
static eportskf_result eport_hid_verify_pin(
    void *implementation,
    const uint8_t pin[EPORTSKF_PIN_SIZE])
{
    eport_hid_device *device = implementation;
    uint8_t verify[5 + EPORTSKF_PIN_SIZE] = {0x00, 0x20, 0x00, 0x82, 0x08};
    uint8_t response[EPORT_HID_RESPONSE_CAPACITY];
    size_t response_length = 0;
    uint16_t status = 0;
    eportskf_result result;

    if (device == NULL || pin == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    memcpy(verify + 5, pin, EPORTSKF_PIN_SIZE);
    result = eport_hid_command(device, verify, sizeof(verify), response, &response_length, &status);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (status == 0x9000) {
        return response_length == 0 ? EPORTSKF_SUCCESS : EPORTSKF_FAILURE;
    }
    if (status == 0x6982) {
        return EPORTSKF_VERIFICATION_REQUIRED;
    }
    if ((status & 0xff00) == 0x6300) {
        return EPORTSKF_PIN_REJECTED;
    }
    return EPORTSKF_FAILURE;
}

/* The token wants the SHA1 digest reversed and returns the signature reversed;
   both are byte-order conventions of this transport, not part of RSA. A 61xx
   response announces the pending length, where xx = 00 means the full 128
   bytes. */
static eportskf_result eport_hid_sign_digest(
    void *implementation,
    const uint8_t *digest,
    uint8_t *signature,
    size_t *length)
{
    eport_hid_device *device = implementation;
    uint8_t sign[EPORT_HID_APDU_CAPACITY] = {0x80, 0xf2, 0x83, 0x00, EPORT_SHA1_DIGEST_SIZE};
    uint8_t get_response[] = {0x00, 0xc0, 0x00, 0x00, 0};
    uint8_t response[EPORT_HID_RESPONSE_CAPACITY];
    size_t response_length = 0;
    uint16_t status = 0;
    size_t index;
    eportskf_result result;

    if (device == NULL || digest == NULL || signature == NULL || length == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    *length = 0;

    for (index = 0; index < EPORT_SHA1_DIGEST_SIZE; ++index) {
        sign[5 + index] = digest[EPORT_SHA1_DIGEST_SIZE - 1 - index];
    }
    result = eport_hid_command(device, sign, sizeof(sign), response, &response_length, &status);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (status == 0x6982) {
        return EPORTSKF_VERIFICATION_REQUIRED;
    }
    if ((status & 0xff00) != 0x6100 || response_length != 0) {
        return EPORTSKF_FAILURE;
    }

    get_response[4] = (uint8_t)(status & 0xff);
    result = eport_hid_command(
        device,
        get_response,
        sizeof(get_response),
        response,
        &response_length,
        &status);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (status == 0x6982) {
        return EPORTSKF_VERIFICATION_REQUIRED;
    }
    if (status != 0x9000 || response_length != EPORTSKF_SIGNATURE_CAPACITY) {
        return EPORTSKF_FAILURE;
    }

    for (index = 0; index < EPORTSKF_SIGNATURE_CAPACITY; ++index) {
        signature[index] = response[EPORTSKF_SIGNATURE_CAPACITY - 1 - index];
    }
    *length = EPORTSKF_SIGNATURE_CAPACITY;
    return EPORTSKF_SUCCESS;
}

static eportskf_result eport_hid_close(void *implementation)
{
    eport_hid_device *device = implementation;
    eportskf_result result;

    if (device == NULL) {
        return EPORTSKF_SUCCESS;
    }
    result = eport_hid_platform_close(device->platform);
    free(device);
    return result;
}

static const eport_device_ops eport_hid_operations = {
    eport_hid_read_certificate,
    eport_hid_verify_pin,
    eport_hid_sign_digest,
    eport_hid_close
};

typedef struct eport_hid_enumeration_context {
    eport_name_visitor visitor;
    void *context;
} eport_hid_enumeration_context;

static eportskf_result eport_hid_prefixed_name(const char *descriptor, void *context)
{
    static const char prefix[] = "[HID] ";
    eport_hid_enumeration_context *enumeration = context;
    size_t descriptor_length;
    char *name;
    eportskf_result result;

    if (descriptor == NULL || descriptor[0] == '\0') {
        return EPORTSKF_FAILURE;
    }
    descriptor_length = strlen(descriptor);
    if (descriptor_length > SIZE_MAX - sizeof(prefix)) {
        return EPORTSKF_FAILURE;
    }

    name = malloc(descriptor_length + sizeof(prefix));
    if (name == NULL) {
        return EPORTSKF_FAILURE;
    }
    memcpy(name, prefix, sizeof(prefix) - 1);
    memcpy(name + sizeof(prefix) - 1, descriptor, descriptor_length + 1);
    result = enumeration->visitor(name, enumeration->context);
    free(name);
    return result;
}

eportskf_result eport_hid_enumerate(eport_name_visitor visitor, void *context)
{
    eport_hid_enumeration_context enumeration;

    if (visitor == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    enumeration.visitor = visitor;
    enumeration.context = context;
    return eport_hid_platform_enumerate(eport_hid_prefixed_name, &enumeration);
}

/* The handle is published only after the token has been unlocked and the
   certificate file selected, so an opened device is ready for commands. Any
   failure closes the platform handle instead of leaking it. */
eportskf_result eport_hid_open(const char *descriptor, eportskf_device **out_device)
{
    eportskf_device *device;
    eport_hid_device *hid;
    eportskf_result result;

    if (out_device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    *out_device = NULL;
    if (descriptor == NULL || descriptor[0] == '\0') {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }

    device = calloc(1, sizeof(*device));
    hid = calloc(1, sizeof(*hid));
    if (device == NULL || hid == NULL) {
        free(device);
        free(hid);
        return EPORTSKF_FAILURE;
    }

    result = eport_hid_platform_open(descriptor, &hid->platform);
    if (result == EPORTSKF_SUCCESS) {
        device->operations = &eport_hid_operations;
        device->implementation = hid;
        device->medium = EPORT_MEDIUM_HID;
        result = eport_hid_initialize(hid);
    }
    if (result != EPORTSKF_SUCCESS) {
        if (hid->platform != NULL) {
            (void)eport_hid_platform_close(hid->platform);
        }
        free(hid);
        free(device);
        return result;
    }

    *out_device = device;
    return EPORTSKF_SUCCESS;
}
