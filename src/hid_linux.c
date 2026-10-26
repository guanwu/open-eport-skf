/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* Linux HID transport for the ePort token over /dev/hidraw.
 *
 * The node is opened non-blocking and every report is bounded by one absolute
 * deadline, so a token that stops answering cannot hold the caller past the
 * session timeout.
 */
#define _POSIX_C_SOURCE 200809L

#include "hid.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/hidraw.h>
#include <linux/input.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define EPORT_HID_VENDOR_ID 0x1a56
#define EPORT_HID_PRODUCT_ID 0xdd01
#define EPORT_HID_TIMEOUT_MS 8000

struct eport_hid_platform_device {
    int descriptor;
};

static int eport_hid_is_hidraw_name(const char *name);

/* hidraw reports the USB vendor, product, and bus type, so discovery needs no
   device database. */
static int eport_hid_has_expected_ids(int descriptor)
{
    struct hidraw_devinfo information;

    memset(&information, 0, sizeof(information));
    return ioctl(descriptor, HIDIOCGRAWINFO, &information) >= 0
        && information.bustype == BUS_USB
        && (uint16_t)information.vendor == EPORT_HID_VENDOR_ID
        && (uint16_t)information.product == EPORT_HID_PRODUCT_ID;
}

static int eport_hid_monotonic_milliseconds(int64_t *milliseconds)
{
    struct timespec time;

    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) {
        return 0;
    }
    *milliseconds = (int64_t)time.tv_sec * 1000 + time.tv_nsec / 1000000;
    return 1;
}

/* Waits for one readiness event against an absolute deadline, so retries after
   EINTR do not extend the session timeout. */
static eportskf_result eport_hid_wait(int descriptor, short events, int64_t deadline)
{
    for (;;) {
        struct pollfd pollfd;
        int64_t now;
        int ready;

        if (!eport_hid_monotonic_milliseconds(&now) || now >= deadline) {
            return EPORTSKF_DEVICE_UNAVAILABLE;
        }
        pollfd.fd = descriptor;
        pollfd.events = events;
        pollfd.revents = 0;
        ready = poll(&pollfd, 1, (int)(deadline - now));
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return EPORTSKF_DEVICE_UNAVAILABLE;
        }
        if (ready == 0) {
            return EPORTSKF_DEVICE_UNAVAILABLE;
        }
        if ((pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            return EPORTSKF_DEVICE_UNAVAILABLE;
        }
        if ((pollfd.revents & events) != 0) {
            return EPORTSKF_SUCCESS;
        }
    }
}

/* Only /dev/hidrawN is accepted, so a name from another source cannot make
   this transport open an unrelated device through its raw file handle. */
eportskf_result eport_hid_platform_open(
    const char *descriptor,
    eport_hid_platform_device **out_device)
{
    int file_descriptor;
    eport_hid_platform_device *device;

    if (out_device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    *out_device = NULL;
    if (descriptor == NULL || descriptor[0] == '\0') {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    if (strncmp(descriptor, "/dev/", 5) != 0 || !eport_hid_is_hidraw_name(descriptor + 5)) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    file_descriptor = open(descriptor, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (file_descriptor < 0) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    if (!eport_hid_has_expected_ids(file_descriptor)) {
        close(file_descriptor);
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    device = calloc(1, sizeof(*device));
    if (device == NULL) {
        close(file_descriptor);
        return EPORTSKF_FAILURE;
    }
    device->descriptor = file_descriptor;
    *out_device = device;
    return EPORTSKF_SUCCESS;
}

/* The descriptor is non-blocking, so a short write or EAGAIN is retried inside
   the deadline; a complete report is the only success. */
eportskf_result eport_hid_platform_write(
    eport_hid_platform_device *device,
    const uint8_t report[EPORT_HID_REPORT_SIZE])
{
    int64_t now;
    int64_t deadline;

    if (device == NULL || report == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    if (!eport_hid_monotonic_milliseconds(&now)) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    deadline = now + EPORT_HID_TIMEOUT_MS;

    for (;;) {
        eportskf_result result = eport_hid_wait(device->descriptor, POLLOUT, deadline);
        ssize_t written;

        if (result != EPORTSKF_SUCCESS) {
            return result;
        }
        written = write(device->descriptor, report, EPORT_HID_REPORT_SIZE);
        if (written == EPORT_HID_REPORT_SIZE) {
            return EPORTSKF_SUCCESS;
        }
        if (written >= 0) {
            return EPORTSKF_DEVICE_UNAVAILABLE;
        }
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            return EPORTSKF_DEVICE_UNAVAILABLE;
        }
    }
}

/* A short read is a protocol failure rather than a retry: the token sends whole
   reports, and a partial one cannot be completed safely. */
eportskf_result eport_hid_platform_read(
    eport_hid_platform_device *device,
    uint8_t report[EPORT_HID_REPORT_SIZE])
{
    int64_t now;
    int64_t deadline;

    if (device == NULL || report == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    if (!eport_hid_monotonic_milliseconds(&now)) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    deadline = now + EPORT_HID_TIMEOUT_MS;

    for (;;) {
        eportskf_result result = eport_hid_wait(device->descriptor, POLLIN, deadline);
        ssize_t count;

        if (result != EPORTSKF_SUCCESS) {
            return result;
        }
        count = read(device->descriptor, report, EPORT_HID_REPORT_SIZE);
        if (count == EPORT_HID_REPORT_SIZE) {
            return EPORTSKF_SUCCESS;
        }
        if (count == 0) {
            return EPORTSKF_DEVICE_UNAVAILABLE;
        }
        if (count > 0) {
            return EPORTSKF_FAILURE;
        }
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            return EPORTSKF_DEVICE_UNAVAILABLE;
        }
    }
}

static int eport_hid_is_hidraw_name(const char *name)
{
    size_t index;

    if (strncmp(name, "hidraw", 6) != 0 || name[6] == '\0') {
        return 0;
    }
    for (index = 6; name[index] != '\0'; ++index) {
        if (name[index] < '0' || name[index] > '9') {
            return 0;
        }
    }
    return 1;
}

/* Every hidraw node is opened and filtered by its USB ids. A node that cannot
   be opened is skipped because it may belong to another user or driver. */
eportskf_result eport_hid_platform_enumerate(eport_name_visitor visitor, void *context)
{
    DIR *directory;
    eportskf_result result = EPORTSKF_SUCCESS;

    if (visitor == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    directory = opendir("/dev");
    if (directory == NULL) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    for (;;) {
        struct dirent *entry;
        size_t name_length;
        char *descriptor;
        int file_descriptor;

        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                result = EPORTSKF_DEVICE_UNAVAILABLE;
            }
            break;
        }
        if (!eport_hid_is_hidraw_name(entry->d_name)) {
            continue;
        }

        name_length = strlen(entry->d_name);
        if (name_length > SIZE_MAX - sizeof("/dev/")) {
            result = EPORTSKF_FAILURE;
            break;
        }
        descriptor = malloc(name_length + sizeof("/dev/"));
        if (descriptor == NULL) {
            result = EPORTSKF_FAILURE;
            break;
        }
        memcpy(descriptor, "/dev/", sizeof("/dev/") - 1);
        memcpy(descriptor + sizeof("/dev/") - 1, entry->d_name, name_length + 1);

        file_descriptor = open(descriptor, O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (file_descriptor < 0) {
            free(descriptor);
            continue;
        }
        if (!eport_hid_has_expected_ids(file_descriptor)) {
            close(file_descriptor);
            free(descriptor);
            continue;
        }
        close(file_descriptor);

        result = visitor(descriptor, context);
        free(descriptor);
        if (result != EPORTSKF_SUCCESS) {
            break;
        }
    }

    if (closedir(directory) != 0 && result == EPORTSKF_SUCCESS) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
    }
    return result;
}

eportskf_result eport_hid_platform_close(eport_hid_platform_device *device)
{
    eportskf_result result = EPORTSKF_SUCCESS;

    if (device == NULL) {
        return EPORTSKF_SUCCESS;
    }
    if (close(device->descriptor) != 0) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
    }
    free(device);
    return result;
}
