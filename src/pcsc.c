/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* ePort smart card application over PC/SC.
 *
 * The card is an ISO 7816 command processor: every exchange is an APDU whose
 * last two response bytes are a status word. This layer selects the
 * application and the container, builds the encrypted PIN block, and maps
 * status words to results; the platform layer only transmits bytes.
 */
#include "pcsc.h"

#include <stdlib.h>
#include <string.h>

/* A certificate response adds a four-byte length prefix and the two-byte
   status word to the bounded DER certificate. */
#define EPORT_PCSC_RESPONSE_CAPACITY (EPORT_CERTIFICATE_CAPACITY + 6)
#define EPORT_PCSC_SIGNATURE_SIZE 64

/* The card state that has to survive between commands: the application is
   selected at open, the container on first use. */
typedef struct eport_pcsc_session {
    eport_pcsc_platform_device *platform;
    int container_selected;
} eport_pcsc_session;

typedef struct eport_pcsc_enumeration_context {
    eport_name_visitor visitor;
    void *context;
} eport_pcsc_enumeration_context;

/* Splits one APDU response into its payload and its trailing status word.
   Anything shorter than two bytes carries no status and is a failure. */
static eportskf_result eport_pcsc_exchange(
    eport_pcsc_session *session,
    const uint8_t *command,
    size_t command_length,
    uint8_t *response,
    size_t response_capacity,
    size_t *payload_length,
    uint16_t *status)
{
    eportskf_result result;
    size_t response_length = response_capacity;

    *payload_length = 0;
    *status = 0;
    result = eport_pcsc_platform_transmit(
        session->platform, command, command_length, response, &response_length);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (response_length > response_capacity || response_length < 2) {
        return EPORTSKF_FAILURE;
    }

    *payload_length = response_length - 2;
    *status = (uint16_t)(((uint16_t)response[response_length - 2] << 8)
        | response[response_length - 1]);
    return EPORTSKF_SUCCESS;
}

/* Selected at open so the first operation does not have to know about the
   application. The container inside it is selected later, on first use. */
static eportskf_result eport_pcsc_select_application(eport_pcsc_session *session)
{
    static const uint8_t command[] = {
        0x80, 0x26, 0x00, 0x00, 0x00, 0x00, 0x0a,
        0x43, 0x48, 0x49, 0x4e, 0x41, 0x45, 0x50, 0x4f, 0x52, 0x54,
        0x00, 0x0a
    };
    uint8_t response[EPORT_PCSC_RESPONSE_CAPACITY];
    size_t payload_length;
    uint16_t status;
    eportskf_result result;

    result = eport_pcsc_exchange(
        session, command, sizeof(command), response, sizeof(response),
        &payload_length, &status);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    return status == 0x9000 ? EPORTSKF_SUCCESS : EPORTSKF_FAILURE;
}

/* The container is selected once per open, because the card keeps it selected
   for the rest of the session. */
static eportskf_result eport_pcsc_select_container(eport_pcsc_session *session)
{
    static const uint8_t command[] = {
        0x80, 0x42, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x2f, 0x01,
        0x45, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x53, 0x41,
        0x00, 0x02
    };
    uint8_t response[EPORT_PCSC_RESPONSE_CAPACITY];
    size_t payload_length;
    uint16_t status;
    eportskf_result result;

    if (session->container_selected) {
        return EPORTSKF_SUCCESS;
    }

    result = eport_pcsc_exchange(
        session, command, sizeof(command), response, sizeof(response),
        &payload_length, &status);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (status != 0x9000) {
        return EPORTSKF_FAILURE;
    }

    session->container_selected = 1;
    return EPORTSKF_SUCCESS;
}

/* The export response repeats the certificate length twice: a four-byte prefix
   and the DER header. Both must describe the same bytes and must fit the
   bounded buffer, so a card that misreports a length is rejected before any
   copy happens. */
static eportskf_result eport_pcsc_read_certificate(
    void *implementation, uint8_t *der, size_t *length)
{
    static const uint8_t command[] = {
        0x80, 0x4e, 0x01, 0x00, 0x00, 0x00, 0x04,
        0x2f, 0x01, 0x2e, 0x01, 0x00, 0x00
    };
    eport_pcsc_session *session = implementation;
    uint8_t response[EPORT_PCSC_RESPONSE_CAPACITY];
    size_t payload_length;
    size_t certificate_length;
    size_t der_length;
    uint16_t status;
    eportskf_result result;

    if (session == NULL || der == NULL || length == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    *length = 0;

    result = eport_pcsc_select_container(session);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    result = eport_pcsc_exchange(
        session, command, sizeof(command), response, sizeof(response),
        &payload_length, &status);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (status != 0x9000 || payload_length < 4) {
        return EPORTSKF_FAILURE;
    }

    certificate_length = ((size_t)response[0] << 24)
        | ((size_t)response[1] << 16)
        | ((size_t)response[2] << 8)
        | (size_t)response[3];
    if (certificate_length < 4
        || certificate_length > EPORT_CERTIFICATE_CAPACITY
        || payload_length - 4 != certificate_length) {
        return EPORTSKF_FAILURE;
    }
    if (response[4] != 0x30 || response[5] != 0x82) {
        return EPORTSKF_FAILURE;
    }

    der_length = ((size_t)response[6] << 8) | response[7];
    if (der_length + 4 != certificate_length) {
        return EPORTSKF_FAILURE;
    }

    memcpy(der, response + 4, certificate_length);
    *length = certificate_length;
    return EPORTSKF_SUCCESS;
}

/* PIN block: SHA1 over the eight PIN bytes followed by eight zero bytes gives
   the SM4 key, whose first 16 bytes are used. The plaintext carries a
   challenge obtained for this attempt, and the challenge is never reused, so
   every verification costs one more command exchange. */
static eportskf_result eport_pcsc_verify_pin(
    void *implementation, const uint8_t pin[EPORTSKF_PIN_SIZE])
{
    static const uint8_t challenge_command[] = {
        0x80, 0x50, 0x00, 0x00, 0x00, 0x00, 0x08
    };
    static const uint8_t verify_prefix[] = {
        0x80, 0x18, 0x00, 0x01, 0x00, 0x00, 0x12, 0x2f, 0x01
    };
    static const uint8_t zero_padding[EPORTSKF_PIN_SIZE] = { 0 };
    eport_pcsc_session *session = implementation;
    uint8_t response[EPORT_PCSC_RESPONSE_CAPACITY];
    uint8_t command[sizeof(verify_prefix) + 16];
    uint8_t plaintext[16] = { 0x08, 0x00 };
    uint8_t key[EPORT_SHA1_DIGEST_SIZE];
    eport_sha1 hash;
    size_t payload_length;
    uint16_t status;
    eportskf_result result;

    if (session == NULL || pin == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }

    result = eport_pcsc_exchange(
        session, challenge_command, sizeof(challenge_command),
        response, sizeof(response), &payload_length, &status);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (status != 0x9000 || payload_length != 8) {
        return EPORTSKF_FAILURE;
    }

    eport_sha1_init(&hash);
    eport_sha1_update(&hash, pin, EPORTSKF_PIN_SIZE);
    eport_sha1_update(&hash, zero_padding, sizeof(zero_padding));
    eport_sha1_final(&hash, key);

    memcpy(plaintext + 2, response, 8);
    plaintext[10] = 0x80;
    memcpy(command, verify_prefix, sizeof(verify_prefix));
    eport_sm4_encrypt_block(key, plaintext, command + sizeof(verify_prefix));

    result = eport_pcsc_exchange(
        session, command, sizeof(command), response, sizeof(response),
        &payload_length, &status);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if ((status & 0xff00U) == 0x6300U) {
        return EPORTSKF_PIN_REJECTED;
    }
    if (status == 0x6982) {
        return EPORTSKF_VERIFICATION_REQUIRED;
    }
    if (status != 0x9000 || payload_length != 0) {
        return EPORTSKF_FAILURE;
    }
    return EPORTSKF_SUCCESS;
}

/* The card answers with a four-byte header that is not part of the signature,
   so the result is exactly the 64 bytes that follow it. */
static eportskf_result eport_pcsc_sign_digest(
    void *implementation,
    const uint8_t *digest,
    uint8_t *signature,
    size_t *length)
{
    static const uint8_t command_prefix[] = {
        0x80, 0x74, 0x02, 0x00, 0x00, 0x00, 0x24,
        0x2f, 0x01, 0x2e, 0x01
    };
    static const uint8_t command_suffix[] = { 0x00, 0x00 };
    eport_pcsc_session *session = implementation;
    uint8_t command[sizeof(command_prefix) + EPORT_SM3_DIGEST_SIZE + sizeof(command_suffix)];
    uint8_t response[EPORT_PCSC_RESPONSE_CAPACITY];
    size_t payload_length;
    uint16_t status;
    eportskf_result result;

    if (session == NULL || digest == NULL || signature == NULL || length == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    *length = 0;

    result = eport_pcsc_select_container(session);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }

    memcpy(command, command_prefix, sizeof(command_prefix));
    memcpy(command + sizeof(command_prefix), digest, EPORT_SM3_DIGEST_SIZE);
    memcpy(
        command + sizeof(command_prefix) + EPORT_SM3_DIGEST_SIZE,
        command_suffix, sizeof(command_suffix));
    result = eport_pcsc_exchange(
        session, command, sizeof(command), response, sizeof(response),
        &payload_length, &status);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (status == 0x6982) {
        return EPORTSKF_VERIFICATION_REQUIRED;
    }
    if (status != 0x9000 || payload_length != EPORT_PCSC_SIGNATURE_SIZE + 4) {
        return EPORTSKF_FAILURE;
    }

    memcpy(signature, response + 4, EPORT_PCSC_SIGNATURE_SIZE);
    *length = EPORT_PCSC_SIGNATURE_SIZE;
    return EPORTSKF_SUCCESS;
}

static eportskf_result eport_pcsc_close(void *implementation)
{
    eport_pcsc_session *session = implementation;
    eportskf_result result;

    if (session == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    result = eport_pcsc_platform_close(session->platform);
    free(session);
    return result;
}

static const eport_device_ops eport_pcsc_operations = {
    eport_pcsc_read_certificate,
    eport_pcsc_verify_pin,
    eport_pcsc_sign_digest,
    eport_pcsc_close
};

static eportskf_result eport_pcsc_visit_reader(const char *reader_name, void *context)
{
    static const char prefix[] = "[PCSC] ";
    eport_pcsc_enumeration_context *enumeration = context;
    size_t reader_length;
    char *name;
    eportskf_result result;

    if (reader_name == NULL) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    reader_length = strlen(reader_name);
    if (reader_length > SIZE_MAX - sizeof(prefix)) {
        return EPORTSKF_FAILURE;
    }

    name = malloc(reader_length + sizeof(prefix));
    if (name == NULL) {
        return EPORTSKF_FAILURE;
    }
    memcpy(name, prefix, sizeof(prefix) - 1);
    memcpy(name + sizeof(prefix) - 1, reader_name, reader_length + 1);
    result = enumeration->visitor(name, enumeration->context);
    free(name);
    return result;
}

eportskf_result eport_pcsc_enumerate(eport_name_visitor visitor, void *context)
{
    eport_pcsc_enumeration_context enumeration;

    if (visitor == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    enumeration.visitor = visitor;
    enumeration.context = context;
    return eport_pcsc_platform_enumerate(eport_pcsc_visit_reader, &enumeration);
}

/* Opens the reader and selects the application, so a returned handle is ready
   for certificate and signature commands. */
eportskf_result eport_pcsc_open(const char *reader_name, eportskf_device **out_device)
{
    eportskf_device *device;
    eport_pcsc_session *session;
    eportskf_result result;

    if (out_device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    *out_device = NULL;
    if (reader_name == NULL || reader_name[0] == '\0') {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }

    device = calloc(1, sizeof(*device));
    session = calloc(1, sizeof(*session));
    if (device == NULL || session == NULL) {
        free(device);
        free(session);
        return EPORTSKF_FAILURE;
    }

    result = eport_pcsc_platform_open(reader_name, &session->platform);
    if (result != EPORTSKF_SUCCESS) {
        free(device);
        free(session);
        return result;
    }
    result = eport_pcsc_select_application(session);
    if (result != EPORTSKF_SUCCESS) {
        eport_pcsc_platform_close(session->platform);
        free(device);
        free(session);
        return result;
    }

    device->operations = &eport_pcsc_operations;
    device->implementation = session;
    device->medium = EPORT_MEDIUM_PCSC;
    *out_device = device;
    return EPORTSKF_SUCCESS;
}
