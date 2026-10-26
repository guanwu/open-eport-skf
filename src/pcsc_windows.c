/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* WinSCard implementation of the PC/SC platform interface.
 *
 * Reader names arrive as UTF-8 and are converted to UTF-16 because the smart
 * card service works in wide characters. Cards are connected in shared mode
 * with both transmission protocols offered, the service chooses one, and that
 * choice is reused for every exchange on that handle.
 */
#include "pcsc.h"

#include <windows.h>
#include <winscard.h>

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

struct eport_pcsc_platform_device {
    SCARDCONTEXT context;
    SCARDHANDLE card;
    DWORD protocol;
};

/* Public names are UTF-8 and the smart card service is UTF-16. Invalid text is
   reported as an unavailable device because a name that cannot be expressed is
   not a device on this system. */
static eportskf_result eport_pcsc_utf8_to_wide(const char *input, wchar_t **out_wide)
{
    wchar_t *wide;
    int length;

    *out_wide = NULL;
    length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, NULL, 0);
    if (length <= 0) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    if ((size_t)length > SIZE_MAX / sizeof(*wide)) {
        return EPORTSKF_FAILURE;
    }

    wide = malloc((size_t)length * sizeof(*wide));
    if (wide == NULL) {
        return EPORTSKF_FAILURE;
    }
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, wide, length) != length) {
        free(wide);
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    *out_wide = wide;
    return EPORTSKF_SUCCESS;
}

static eportskf_result eport_pcsc_wide_to_utf8(const wchar_t *input, char **out_utf8)
{
    char *utf8;
    int length;

    *out_utf8 = NULL;
    length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, -1, NULL, 0, NULL, NULL);
    if (length <= 0) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    utf8 = malloc((size_t)length);
    if (utf8 == NULL) {
        return EPORTSKF_FAILURE;
    }
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, input, -1, utf8, length, NULL, NULL) != length) {
        free(utf8);
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    *out_utf8 = utf8;
    return EPORTSKF_SUCCESS;
}

/* SCardListReaders reports the required buffer size on the first call and the
   double-NUL-terminated name list on the second. No readers is an empty
   enumeration, not a failure. */
eportskf_result eport_pcsc_platform_enumerate(eport_name_visitor visitor, void *context)
{
    static const wchar_t all_readers[] = L"SCard$AllReaders";
    SCARDCONTEXT smart_card_context = 0;
    wchar_t *readers = NULL;
    wchar_t *reader;
    DWORD readers_capacity = 0;
    DWORD readers_length;
    size_t remaining;
    LONG status;
    eportskf_result result = EPORTSKF_SUCCESS;

    if (visitor == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }

    status = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &smart_card_context);
    if (status != SCARD_S_SUCCESS) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    status = SCardListReadersW(smart_card_context, all_readers, NULL, &readers_capacity);
    if (status == SCARD_E_NO_READERS_AVAILABLE) {
        goto cleanup;
    }
    if (status != SCARD_S_SUCCESS) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
        goto cleanup;
    }
    if (readers_capacity <= 1) {
        goto cleanup;
    }
    if ((size_t)readers_capacity > SIZE_MAX / sizeof(*readers)) {
        result = EPORTSKF_FAILURE;
        goto cleanup;
    }

    readers = malloc((size_t)readers_capacity * sizeof(*readers));
    if (readers == NULL) {
        result = EPORTSKF_FAILURE;
        goto cleanup;
    }
    readers_length = readers_capacity;
    status = SCardListReadersW(smart_card_context, all_readers, readers, &readers_length);
    if (status == SCARD_E_NO_READERS_AVAILABLE) {
        goto cleanup;
    }
    if (status != SCARD_S_SUCCESS) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
        goto cleanup;
    }
    if (readers_length > readers_capacity) {
        result = EPORTSKF_FAILURE;
        goto cleanup;
    }

    reader = readers;
    remaining = readers_length;
    while (remaining > 0 && *reader != L'\0') {
        const wchar_t *terminator = wmemchr(reader, L'\0', remaining);
        char *reader_name;
        size_t consumed;

        if (terminator == NULL) {
            result = EPORTSKF_FAILURE;
            goto cleanup;
        }
        result = eport_pcsc_wide_to_utf8(reader, &reader_name);
        if (result != EPORTSKF_SUCCESS) {
            goto cleanup;
        }
        result = visitor(reader_name, context);
        free(reader_name);
        if (result != EPORTSKF_SUCCESS) {
            goto cleanup;
        }

        consumed = (size_t)(terminator - reader) + 1;
        reader += consumed;
        remaining -= consumed;
    }

cleanup:
    free(readers);
    if (SCardReleaseContext(smart_card_context) != SCARD_S_SUCCESS && result == EPORTSKF_SUCCESS) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
    }
    return result;
}

/* Shared mode keeps the reader available to other applications, and offering
   both protocols lets the service choose the one the card supports. */
eportskf_result eport_pcsc_platform_open(
    const char *reader_name, eport_pcsc_platform_device **out_device)
{
    eport_pcsc_platform_device *device;
    wchar_t *wide_reader_name;
    eportskf_result result;
    LONG status;

    if (out_device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    *out_device = NULL;
    if (reader_name == NULL || reader_name[0] == '\0') {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }

    result = eport_pcsc_utf8_to_wide(reader_name, &wide_reader_name);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    device = calloc(1, sizeof(*device));
    if (device == NULL) {
        free(wide_reader_name);
        return EPORTSKF_FAILURE;
    }

    status = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &device->context);
    if (status != SCARD_S_SUCCESS) {
        free(device);
        free(wide_reader_name);
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    status = SCardConnectW(
        device->context,
        wide_reader_name,
        SCARD_SHARE_SHARED,
        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
        &device->card,
        &device->protocol);
    free(wide_reader_name);
    if (status != SCARD_S_SUCCESS) {
        SCardReleaseContext(device->context);
        free(device);
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    *out_device = device;
    return EPORTSKF_SUCCESS;
}

/* SCardTransmit reports transport failures only. Card status words come back
   inside the response and are interpreted by the session above. */
eportskf_result eport_pcsc_platform_transmit(
    eport_pcsc_platform_device *device,
    const uint8_t *command,
    size_t command_length,
    uint8_t *response,
    size_t *response_length)
{
    SCARD_IO_REQUEST send_pci;
    size_t response_capacity;
    DWORD received_length;
    LONG status;

    if (device == NULL || command == NULL || response == NULL || response_length == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    response_capacity = *response_length;
    if (command_length > UINT32_MAX || response_capacity > UINT32_MAX) {
        *response_length = 0;
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }

    send_pci.dwProtocol = device->protocol;
    send_pci.cbPciLength = sizeof(send_pci);
    received_length = (DWORD)response_capacity;
    status = SCardTransmit(
        device->card,
        &send_pci,
        command,
        (DWORD)command_length,
        NULL,
        response,
        &received_length);
    if (status != SCARD_S_SUCCESS) {
        *response_length = 0;
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    if ((size_t)received_length > response_capacity) {
        *response_length = 0;
        return EPORTSKF_FAILURE;
    }

    *response_length = received_length;
    return EPORTSKF_SUCCESS;
}

/* Unpowering the card resets it, which also drops any authorization the card
   tracked; the caller has already discarded its local state. */
eportskf_result eport_pcsc_platform_close(eport_pcsc_platform_device *device)
{
    eportskf_result result = EPORTSKF_SUCCESS;

    if (device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    if (SCardDisconnect(device->card, SCARD_UNPOWER_CARD) != SCARD_S_SUCCESS) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
    }
    if (SCardReleaseContext(device->context) != SCARD_S_SUCCESS) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
    }
    free(device);
    return result;
}
