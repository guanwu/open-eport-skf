/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* Session state shared by the public API and both media.
 *
 * eport_device_ops is the whole contract a medium implements: read one DER
 * certificate, verify a PIN, sign a finished digest, and close. Media own
 * their transport and translate card status into results; caching,
 * authorization, and signature sequencing live in api.c so both media behave
 * identically through the public interface.
 */
#ifndef EPORTSKF_INTERNAL_H
#define EPORTSKF_INTERNAL_H

#include "certificate.h"
#include "crypto.h"
#include "eportskf.h"

#include <stddef.h>
#include <stdint.h>

typedef enum eport_medium {
    EPORT_MEDIUM_PCSC,
    EPORT_MEDIUM_HID
} eport_medium;

/* A name visitor returns success to continue the enumeration and any other
   result to stop it. Names are UTF-8. */
typedef eportskf_result (*eport_name_visitor)(const char *name, void *context);

/* Every operation reports what the card or token answered, translated into
   public results. read_certificate fills der, whose capacity is
   EPORT_CERTIFICATE_CAPACITY, and sets *length; verify_pin receives the
   validated PIN bytes; sign_digest receives one finished digest and sets
   *length to the signature size; close releases the implementation. */
typedef struct eport_device_ops {
    eportskf_result (*read_certificate)(void *implementation, uint8_t *der, size_t *length);
    eportskf_result (*verify_pin)(void *implementation, const uint8_t pin[EPORTSKF_PIN_SIZE]);
    eportskf_result (*sign_digest)(void *implementation, const uint8_t *digest, uint8_t *signature, size_t *length);
    eportskf_result (*close)(void *implementation);
} eport_device_ops;

struct eportskf_device {
    const eport_device_ops *operations;
    void *implementation;
    eport_medium medium;
    /* Set by a successful PIN verification and cleared whenever the session
       can no longer be trusted: close, transport loss, reset, timeout, or a
       6982 signing response. */
    int authorized;
    /* Nonzero between sign_start and sign_finish or sign_abort. */
    int signing;
    /* Nonzero once certificate holds a successfully parsed certificate. */
    int certificate_ready;
    eport_certificate certificate;
    /* The medium selects the member: SM3 for PC/SC, SHA1 for HID. */
    union {
        eport_sha1 sha1;
        eport_sm3 sm3;
    } hash;
};

eportskf_result eport_pcsc_open(const char *reader_name, eportskf_device **out_device);
eportskf_result eport_pcsc_enumerate(eport_name_visitor visitor, void *context);
eportskf_result eport_hid_open(const char *descriptor, eportskf_device **out_device);
eportskf_result eport_hid_enumerate(eport_name_visitor visitor, void *context);

#endif
