/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* HID platform transport.
 *
 * A platform layer exchanges one report and applies the session timeout.
 * Report framing and stream length handling belong to the session above.
 */
#ifndef EPORTSKF_HID_H
#define EPORTSKF_HID_H

#include "internal.h"

#include <stddef.h>
#include <stdint.h>

/* One report: a report-ID byte followed by seven stream bytes. */
#define EPORT_HID_REPORT_SIZE 8

typedef struct eport_hid_platform_device eport_hid_platform_device;

eportskf_result eport_hid_platform_enumerate(eport_name_visitor visitor, void *context);
eportskf_result eport_hid_platform_open(const char *descriptor, eport_hid_platform_device **out_device);
eportskf_result eport_hid_platform_write(eport_hid_platform_device *device, const uint8_t report[EPORT_HID_REPORT_SIZE]);
eportskf_result eport_hid_platform_read(eport_hid_platform_device *device, uint8_t report[EPORT_HID_REPORT_SIZE]);
eportskf_result eport_hid_platform_close(eport_hid_platform_device *device);

#endif
