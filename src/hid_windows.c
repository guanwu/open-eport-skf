/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* Windows HID transport for the ePort token.
 *
 * Discovery walks the HID device interfaces reported by SetupAPI and keeps
 * only the ePort vendor and product ids. Reports are exchanged through
 * overlapped handles so a stalled token cannot block the caller: a pending
 * operation waits on an event for the session timeout and is cancelled when
 * that wait expires.
 */
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
#  undef _WIN32_WINNT
#  define _WIN32_WINNT 0x0600
#endif

#include "hid.h"

#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>

#include <stdlib.h>
#include <string.h>

#define EPORT_HID_VENDOR_ID 0x1a56
#define EPORT_HID_PRODUCT_ID 0xdd01
#define EPORT_HID_TIMEOUT_MS 8000

struct eport_hid_platform_device {
    HANDLE handle;
    HANDLE event;
};

/* The public name carries UTF-8 and the setup API works in UTF-16, so every
   conversion goes through these two helpers. */
static wchar_t *eport_hid_utf8_to_wide(const char *text)
{
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    wchar_t *wide;

    if (length <= 0) {
        return NULL;
    }
    wide = malloc((size_t)length * sizeof(*wide));
    if (wide == NULL) {
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, wide, length) != length) {
        free(wide);
        return NULL;
    }
    return wide;
}

static char *eport_hid_wide_to_utf8(const wchar_t *text)
{
    int length = WideCharToMultiByte(CP_UTF8, 0, text, -1, NULL, 0, NULL, NULL);
    char *utf8;

    if (length <= 0) {
        return NULL;
    }
    utf8 = malloc((size_t)length);
    if (utf8 == NULL) {
        return NULL;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, length, NULL, NULL) != length) {
        free(utf8);
        return NULL;
    }
    return utf8;
}

/* Only the ePort ids are accepted: the interface path shape is shared with
   every other HID device, so the ids are the only reliable discriminator. */
static int eport_hid_has_expected_ids(HANDLE handle)
{
    HIDD_ATTRIBUTES attributes;

    memset(&attributes, 0, sizeof(attributes));
    attributes.Size = sizeof(attributes);
    return HidD_GetAttributes(handle, &attributes)
        && attributes.VendorID == EPORT_HID_VENDOR_ID
        && attributes.ProductID == EPORT_HID_PRODUCT_ID;
}

/* The descriptor is a device-interface path rather than a file path, so the
   vendor and product ids are verified again after opening to reject a stale
   path that now belongs to another device. */
eportskf_result eport_hid_platform_open(
    const char *descriptor,
    eport_hid_platform_device **out_device)
{
    wchar_t *path;
    HANDLE handle;
    eport_hid_platform_device *device;

    if (out_device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    *out_device = NULL;
    if (descriptor == NULL || descriptor[0] == '\0') {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }

    path = eport_hid_utf8_to_wide(descriptor);
    if (path == NULL) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    handle = CreateFileW(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);
    free(path);
    if (handle == INVALID_HANDLE_VALUE) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    if (!eport_hid_has_expected_ids(handle)) {
        CloseHandle(handle);
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    device = calloc(1, sizeof(*device));
    if (device == NULL) {
        CloseHandle(handle);
        return EPORTSKF_FAILURE;
    }
    device->event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (device->event == NULL) {
        CloseHandle(handle);
        free(device);
        return EPORTSKF_FAILURE;
    }
    device->handle = handle;
    *out_device = device;
    return EPORTSKF_SUCCESS;
}

/* One overlapped read or write on the manual-reset event. The request can
   complete inline; a pending request waits for the event and is cancelled when
   that wait expires, so a stalled token cannot block the caller and the handle
   stays valid for the close path. */
static eportskf_result eport_hid_transfer(
    eport_hid_platform_device *device,
    const uint8_t *report,
    int writing)
{
    OVERLAPPED overlapped;
    DWORD transferred = 0;
    BOOL io_started;

    if (!ResetEvent(device->event)) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = device->event;

    if (writing) {
        io_started = WriteFile(
            device->handle,
            report,
            EPORT_HID_REPORT_SIZE,
            &transferred,
            &overlapped);
    } else {
        io_started = ReadFile(
            device->handle,
            (uint8_t *)report,
            EPORT_HID_REPORT_SIZE,
            &transferred,
            &overlapped);
    }

    if (!io_started) {
        DWORD wait_result;

        if (GetLastError() != ERROR_IO_PENDING) {
            return EPORTSKF_DEVICE_UNAVAILABLE;
        }
        wait_result = WaitForSingleObject(device->event, EPORT_HID_TIMEOUT_MS);
        if (wait_result != WAIT_OBJECT_0) {
            DWORD ignored = 0;

            (void)CancelIoEx(device->handle, &overlapped);
            (void)GetOverlappedResult(device->handle, &overlapped, &ignored, TRUE);
            return EPORTSKF_DEVICE_UNAVAILABLE;
        }
    }

    if (!GetOverlappedResult(device->handle, &overlapped, &transferred, TRUE)) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    if (transferred != EPORT_HID_REPORT_SIZE) {
        return writing ? EPORTSKF_DEVICE_UNAVAILABLE : EPORTSKF_FAILURE;
    }
    return EPORTSKF_SUCCESS;
}

eportskf_result eport_hid_platform_write(
    eport_hid_platform_device *device,
    const uint8_t report[EPORT_HID_REPORT_SIZE])
{
    if (device == NULL || report == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    return eport_hid_transfer(device, report, 1);
}

eportskf_result eport_hid_platform_read(
    eport_hid_platform_device *device,
    uint8_t report[EPORT_HID_REPORT_SIZE])
{
    if (device == NULL || report == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    return eport_hid_transfer(device, report, 0);
}

/* Every present HID interface is examined, and the ones with another vendor or
   product id are skipped after a brief open; SetupAPI does not expose those ids
   without opening the device. */
eportskf_result eport_hid_platform_enumerate(eport_name_visitor visitor, void *context)
{
    GUID hid_guid;
    HDEVINFO device_set;
    DWORD index = 0;
    eportskf_result result = EPORTSKF_SUCCESS;

    if (visitor == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }

    HidD_GetHidGuid(&hid_guid);
    device_set = SetupDiGetClassDevsW(&hid_guid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (device_set == INVALID_HANDLE_VALUE) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    for (;;) {
        SP_DEVICE_INTERFACE_DATA interface_data;
        DWORD required_size = 0;
        PSP_DEVICE_INTERFACE_DETAIL_DATA_W detail;
        HANDLE handle;
        char *descriptor;

        memset(&interface_data, 0, sizeof(interface_data));
        interface_data.cbSize = sizeof(interface_data);
        if (!SetupDiEnumDeviceInterfaces(device_set, NULL, &hid_guid, index, &interface_data)) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) {
                result = EPORTSKF_DEVICE_UNAVAILABLE;
            }
            break;
        }
        ++index;

        if (SetupDiGetDeviceInterfaceDetailW(device_set, &interface_data, NULL, 0, &required_size, NULL)
            || GetLastError() != ERROR_INSUFFICIENT_BUFFER
            || required_size < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
            continue;
        }
        detail = malloc(required_size);
        if (detail == NULL) {
            result = EPORTSKF_FAILURE;
            break;
        }
        memset(detail, 0, (size_t)required_size);
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        if (!SetupDiGetDeviceInterfaceDetailW(
                device_set,
                &interface_data,
                detail,
                required_size,
                NULL,
                NULL)) {
            free(detail);
            continue;
        }

        handle = CreateFileW(
            detail->DevicePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            NULL);
        if (handle == INVALID_HANDLE_VALUE) {
            free(detail);
            continue;
        }
        if (!eport_hid_has_expected_ids(handle)) {
            CloseHandle(handle);
            free(detail);
            continue;
        }
        CloseHandle(handle);

        descriptor = eport_hid_wide_to_utf8(detail->DevicePath);
        free(detail);
        if (descriptor == NULL) {
            continue;
        }
        result = visitor(descriptor, context);
        free(descriptor);
        if (result != EPORTSKF_SUCCESS) {
            break;
        }
    }

    SetupDiDestroyDeviceInfoList(device_set);
    return result;
}

eportskf_result eport_hid_platform_close(eport_hid_platform_device *device)
{
    eportskf_result result = EPORTSKF_SUCCESS;

    if (device == NULL) {
        return EPORTSKF_SUCCESS;
    }
    if (device->handle != INVALID_HANDLE_VALUE && !CloseHandle(device->handle)) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
    }
    if (device->event != NULL && !CloseHandle(device->event)) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
    }
    free(device);
    return result;
}
