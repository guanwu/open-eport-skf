/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* Identity and SM2 public point of one device certificate. */
#ifndef EPORTSKF_CERTIFICATE_H
#define EPORTSKF_CERTIFICATE_H

#include "eportskf.h"

#include <stddef.h>
#include <stdint.h>

/* Both limits are enforced during parsing, so the certificate and extension
   sizes stay bounded whatever the device sends. */
#define EPORT_CERTIFICATE_CAPACITY 2048
#define EPORT_EXTENSION_CAPACITY 512

/* Identity fields are NUL-terminated. The public point holds x||y, 32 bytes
   each, and is present only for SM2 certificates. */
typedef struct eport_certificate {
    char *cert_id;
    char *device_id;
    uint8_t sm2_public_key[64];
    int has_sm2_public_key;
} eport_certificate;

/* Parses one bounded DER certificate into owned strings. The output is reset
   first, so a failure leaves nothing to release. */
eportskf_result eport_certificate_parse(const uint8_t *der, size_t length, eport_certificate *out_certificate);

/* Resets the structure, which makes a second free harmless. */
void eport_certificate_free(eport_certificate *certificate);

#endif
