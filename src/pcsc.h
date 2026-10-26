/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* PC/SC platform transport.
 *
 * A platform layer moves one APDU and reports transport failures. Status
 * words are card data: they stay in the response buffer and are interpreted
 * by the session above.
 */
#ifndef EPORTSKF_PCSC_H
#define EPORTSKF_PCSC_H

#include "internal.h"

#include <stddef.h>
#include <stdint.h>

typedef struct eport_pcsc_platform_device eport_pcsc_platform_device;

eportskf_result eport_pcsc_platform_enumerate(eport_name_visitor visitor, void *context);
eportskf_result eport_pcsc_platform_open(const char *reader_name, eport_pcsc_platform_device **out_device);
eportskf_result eport_pcsc_platform_transmit(
    eport_pcsc_platform_device *device,
    const uint8_t *command,
    size_t command_length,
    uint8_t *response,
    size_t *response_length);
eportskf_result eport_pcsc_platform_close(eport_pcsc_platform_device *device);

#endif
