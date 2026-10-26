/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* Bounded DER reader for device certificates.
 *
 * Only three fields are interpreted: the serial number, the device-number
 * extension, and the SM2 public point. Every length is checked against the
 * object that contains it, and each container must be consumed exactly, so a
 * truncated or padded certificate is rejected instead of partly trusted. The
 * whole parse runs inside the caller's 2048-byte buffer and allocates only the
 * two identity strings.
 */
#include "certificate.h"

#include <stdlib.h>
#include <string.h>

typedef struct eport_der_value {
    uint8_t tag;
    const uint8_t *content;
    size_t content_length;
} eport_der_value;

typedef struct eport_der_reader {
    const uint8_t *bytes;
    size_t length;
    size_t position;
} eport_der_reader;

/* DER content bytes of 1.3.6.1.4.1.5315.100.5.9, the device-number extension,
   and of 1.2.156.10197.1.301, the SM2 key and named-curve identifier. */
static const uint8_t eport_device_oid[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xa9, 0x43, 0x64, 0x05, 0x09
};
static const uint8_t eport_sm2_oid[] = {
    0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d
};

static eport_der_reader eport_der_contents(const eport_der_value *value)
{
    eport_der_reader reader;

    reader.bytes = value->content;
    reader.length = value->content_length;
    reader.position = 0;
    return reader;
}

static int eport_der_has_tag(const eport_der_reader *reader, uint8_t tag)
{
    return reader->position < reader->length && reader->bytes[reader->position] == tag;
}

/* Accepts definite short, 0x81, and 0x82 lengths, which is what certificates
   and extension values use. Indefinite and longer forms are rejected instead
   of skipped: a length the reader cannot verify makes the next offset
   meaningless. */
static int eport_der_read(eport_der_reader *reader, eport_der_value *value)
{
    uint8_t first_length;
    size_t content_length;

    if (reader->position >= reader->length) {
        return 0;
    }
    value->tag = reader->bytes[reader->position++];
    if (reader->position >= reader->length) {
        return 0;
    }
    first_length = reader->bytes[reader->position++];
    if (first_length < 0x80) {
        content_length = first_length;
    } else if (first_length == 0x81) {
        if (reader->position >= reader->length) {
            return 0;
        }
        content_length = reader->bytes[reader->position++];
    } else if (first_length == 0x82) {
        if (reader->length - reader->position < 2) {
            return 0;
        }
        content_length = ((size_t)reader->bytes[reader->position] << 8) |
            reader->bytes[reader->position + 1];
        reader->position += 2;
    } else {
        return 0;
    }
    if (content_length > reader->length - reader->position) {
        return 0;
    }
    value->content = reader->bytes + reader->position;
    value->content_length = content_length;
    reader->position += content_length;
    return 1;
}

static int eport_der_expect(
    eport_der_reader *reader,
    uint8_t tag,
    eport_der_value *value)
{
    return eport_der_read(reader, value) && value->tag == tag;
}

static int eport_der_done(const eport_der_reader *reader)
{
    return reader->position == reader->length;
}

static int eport_oid_equals(
    const eport_der_value *value,
    const uint8_t *oid,
    size_t oid_length)
{
    return value->content_length == oid_length &&
        memcmp(value->content, oid, oid_length) == 0;
}

/* The certificate ID is the serial content bytes in lowercase hexadecimal, so
   leading zero bytes stay visible and the length follows the encoding. */
static eportskf_result eport_read_serial(
    const eport_der_value *serial,
    eport_certificate *certificate)
{
    static const char digits[] = "0123456789abcdef";
    size_t index;

    if (serial->content_length == 0) {
        return EPORTSKF_FAILURE;
    }
    certificate->cert_id = malloc(serial->content_length * 2 + 1);
    if (certificate->cert_id == NULL) {
        return EPORTSKF_FAILURE;
    }
    for (index = 0; index < serial->content_length; ++index) {
        certificate->cert_id[index * 2] = digits[serial->content[index] >> 4];
        certificate->cert_id[index * 2 + 1] = digits[serial->content[index] & 0x0f];
    }
    certificate->cert_id[serial->content_length * 2] = '\0';
    return EPORTSKF_SUCCESS;
}

/* The algorithm identifier names SM2 either as the algorithm OID or as its
   named-curve parameter, and both spellings describe the same key. Other key
   types are accepted without a point because the identity fields are still
   useful; only ZA construction needs the coordinates. */
static eportskf_result eport_parse_public_key(
    const eport_der_value *subject_public_key_info,
    eport_certificate *certificate)
{
    eport_der_reader reader = eport_der_contents(subject_public_key_info);
    eport_der_value algorithm_value;
    eport_der_reader algorithm;
    eport_der_value oid;
    eport_der_value parameters;
    eport_der_value public_key;
    int is_sm2;

    if (!eport_der_expect(&reader, 0x30, &algorithm_value)) {
        return EPORTSKF_FAILURE;
    }
    algorithm = eport_der_contents(&algorithm_value);
    if (!eport_der_expect(&algorithm, 0x06, &oid)) {
        return EPORTSKF_FAILURE;
    }
    is_sm2 = eport_oid_equals(&oid, eport_sm2_oid, sizeof(eport_sm2_oid));
    if (!eport_der_done(&algorithm)) {
        if (!eport_der_read(&algorithm, &parameters)) {
            return EPORTSKF_FAILURE;
        }
        if (parameters.tag == 0x06 &&
            eport_oid_equals(&parameters, eport_sm2_oid, sizeof(eport_sm2_oid))) {
            is_sm2 = 1;
        }
        if (!eport_der_done(&algorithm)) {
            return EPORTSKF_FAILURE;
        }
    }
    if (!eport_der_expect(&reader, 0x03, &public_key) || !eport_der_done(&reader)) {
        return EPORTSKF_FAILURE;
    }
    if (!is_sm2) {
        return EPORTSKF_SUCCESS;
    }
    if (public_key.content_length != 66 || public_key.content[0] != 0 ||
        public_key.content[1] != 0x04) {
        return EPORTSKF_FAILURE;
    }
    memcpy(certificate->sm2_public_key, public_key.content + 2, 64);
    certificate->has_sm2_public_key = 1;
    return EPORTSKF_SUCCESS;
}

/* The extension body holds exactly one text string. A leading NN- batch prefix
   is removed before validation, and bytes that a C string cannot carry (NUL or
   a high bit) make the certificate invalid rather than being silently
   truncated. */
static eportskf_result eport_parse_device_id(
    const eport_der_value *extension_value,
    eport_certificate *certificate)
{
    eport_der_reader reader = eport_der_contents(extension_value);
    eport_der_value text;
    const uint8_t *bytes;
    size_t length;
    size_t index;

    if (!eport_der_read(&reader, &text) || !eport_der_done(&reader)) {
        return EPORTSKF_FAILURE;
    }
    if (text.tag != 0x0c && text.tag != 0x13 && text.tag != 0x16) {
        return EPORTSKF_FAILURE;
    }
    bytes = text.content;
    length = text.content_length;
    if (length >= 3 &&
        bytes[0] >= '0' && bytes[0] <= '9' &&
        bytes[1] >= '0' && bytes[1] <= '9' && bytes[2] == '-') {
        bytes += 3;
        length -= 3;
    }
    for (index = 0; index < length; ++index) {
        if (bytes[index] == 0 || bytes[index] >= 0x80) {
            return EPORTSKF_FAILURE;
        }
    }
    certificate->device_id = malloc(length + 1);
    if (certificate->device_id == NULL) {
        return EPORTSKF_FAILURE;
    }
    if (length != 0) {
        memcpy(certificate->device_id, bytes, length);
    }
    certificate->device_id[length] = '\0';
    return EPORTSKF_SUCCESS;
}

/* Extensions are a sequence of wrapper objects. The critical flag is accepted
   but not interpreted, because the only extension that is read is optional. */
static eportskf_result eport_parse_extensions(
    const eport_der_value *wrapper,
    eport_certificate *certificate)
{
    eport_der_reader explicit_content = eport_der_contents(wrapper);
    eport_der_value sequence_value;
    eport_der_reader sequence;

    if (!eport_der_expect(&explicit_content, 0x30, &sequence_value) ||
        !eport_der_done(&explicit_content)) {
        return EPORTSKF_FAILURE;
    }
    sequence = eport_der_contents(&sequence_value);
    while (!eport_der_done(&sequence)) {
        eport_der_value extension_value;
        eport_der_reader extension;
        eport_der_value oid;
        eport_der_value critical;
        eport_der_value encoded_text;
        eportskf_result result;

        if (!eport_der_expect(&sequence, 0x30, &extension_value)) {
            return EPORTSKF_FAILURE;
        }
        extension = eport_der_contents(&extension_value);
        if (!eport_der_expect(&extension, 0x06, &oid)) {
            return EPORTSKF_FAILURE;
        }
        if (eport_der_has_tag(&extension, 0x01)) {
            if (!eport_der_read(&extension, &critical) || critical.content_length != 1) {
                return EPORTSKF_FAILURE;
            }
        }
        if (!eport_der_expect(&extension, 0x04, &encoded_text) ||
            !eport_der_done(&extension)) {
            return EPORTSKF_FAILURE;
        }
        if (eport_oid_equals(&oid, eport_device_oid, sizeof(eport_device_oid))) {
            if (certificate->device_id != NULL || encoded_text.content_length > EPORT_EXTENSION_CAPACITY) {
                return EPORTSKF_FAILURE;
            }
            result = eport_parse_device_id(&encoded_text, certificate);
            if (result != EPORTSKF_SUCCESS) {
                return result;
            }
        }
    }
    return EPORTSKF_SUCCESS;
}

/* TBSCertificate orders its fields by the standard: optional version, serial,
   signature, issuer, validity, subject, subjectPublicKeyInfo, then optional
   unique identifiers and extensions. Only the serial and the public key are
   kept; the other fields are validated for presence and skipped. */
static eportskf_result eport_parse_tbs(
    const eport_der_value *tbs_value,
    eport_certificate *certificate)
{
    eport_der_reader tbs = eport_der_contents(tbs_value);
    eport_der_value value;
    eportskf_result result;

    if (eport_der_has_tag(&tbs, 0xa0) && !eport_der_read(&tbs, &value)) {
        return EPORTSKF_FAILURE;
    }
    if (!eport_der_expect(&tbs, 0x02, &value)) {
        return EPORTSKF_FAILURE;
    }
    result = eport_read_serial(&value, certificate);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (!eport_der_expect(&tbs, 0x30, &value) ||
        !eport_der_expect(&tbs, 0x30, &value) ||
        !eport_der_expect(&tbs, 0x30, &value) ||
        !eport_der_expect(&tbs, 0x30, &value) ||
        !eport_der_expect(&tbs, 0x30, &value)) {
        return EPORTSKF_FAILURE;
    }
    result = eport_parse_public_key(&value, certificate);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (eport_der_has_tag(&tbs, 0x81) && !eport_der_read(&tbs, &value)) {
        return EPORTSKF_FAILURE;
    }
    if (eport_der_has_tag(&tbs, 0x82) && !eport_der_read(&tbs, &value)) {
        return EPORTSKF_FAILURE;
    }
    if (eport_der_has_tag(&tbs, 0xa3)) {
        if (!eport_der_read(&tbs, &value)) {
            return EPORTSKF_FAILURE;
        }
        result = eport_parse_extensions(&value, certificate);
        if (result != EPORTSKF_SUCCESS) {
            return result;
        }
    }
    return eport_der_done(&tbs) ? EPORTSKF_SUCCESS : EPORTSKF_FAILURE;
}

static eportskf_result eport_parse_certificate(
    const uint8_t *der,
    size_t length,
    eport_certificate *certificate)
{
    eport_der_reader input = {der, length, 0};
    eport_der_value certificate_value;
    eport_der_reader contents;
    eport_der_value tbs;
    eport_der_value ignored;
    eportskf_result result;

    if (!eport_der_expect(&input, 0x30, &certificate_value) || !eport_der_done(&input)) {
        return EPORTSKF_FAILURE;
    }
    contents = eport_der_contents(&certificate_value);
    if (!eport_der_expect(&contents, 0x30, &tbs)) {
        return EPORTSKF_FAILURE;
    }
    result = eport_parse_tbs(&tbs, certificate);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    if (!eport_der_expect(&contents, 0x30, &ignored) ||
        !eport_der_expect(&contents, 0x03, &ignored) ||
        !eport_der_done(&contents)) {
        return EPORTSKF_FAILURE;
    }
    return EPORTSKF_SUCCESS;
}

/* A certificate without the device-number extension still has an identity, so
   the field becomes an empty string rather than a null pointer. */
static char *eport_empty_text(void)
{
    char *text = malloc(1);

    if (text != NULL) {
        text[0] = '\0';
    }
    return text;
}

eportskf_result eport_certificate_parse(
    const uint8_t *der,
    size_t length,
    eport_certificate *out_certificate)
{
    eport_certificate certificate;
    eportskf_result result;

    if (out_certificate == NULL) {
        return EPORTSKF_FAILURE;
    }
    memset(out_certificate, 0, sizeof(*out_certificate));
    if (der == NULL || length == 0 || length > EPORT_CERTIFICATE_CAPACITY) {
        return EPORTSKF_FAILURE;
    }
    memset(&certificate, 0, sizeof(certificate));
    result = eport_parse_certificate(der, length, &certificate);
    if (result == EPORTSKF_SUCCESS) {
        if (certificate.device_id == NULL) {
            certificate.device_id = eport_empty_text();
        }
        if (certificate.device_id == NULL) {
            result = EPORTSKF_FAILURE;
        }
    }
    if (result != EPORTSKF_SUCCESS) {
        eport_certificate_free(&certificate);
        return result;
    }
    *out_certificate = certificate;
    return EPORTSKF_SUCCESS;
}

void eport_certificate_free(eport_certificate *certificate)
{
    if (certificate == NULL) {
        return;
    }
    free(certificate->cert_id);
    free(certificate->device_id);
    memset(certificate, 0, sizeof(*certificate));
}
