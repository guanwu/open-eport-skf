/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* PC/SC platform interface over the system smart card service.
 *
 * The service library is opened at run time instead of linked: the library and
 * the tool must load on a machine without a smart card daemon, where a missing
 * service is an unavailable device rather than a load-time failure.
 */
#include "pcsc.h"

#include <dlfcn.h>

#include <stdlib.h>
#include <string.h>

#define EPORT_PCSC_NO_READERS_AVAILABLE ((eport_pcsc_long)0x8010002eUL)
#define EPORT_PCSC_SCOPE_SYSTEM 2U
#define EPORT_PCSC_SHARE_SHARED 2U
#define EPORT_PCSC_PROTOCOL_T0 1U
#define EPORT_PCSC_PROTOCOL_T1 2U
#define EPORT_PCSC_UNPOWER_CARD 2U

/* pcsclite declares its handles and status codes as long, which is wider than
   the Windows equivalents; the local aliases keep the declarations below close
   to the service's own prototypes. */
typedef long eport_pcsc_long;
typedef unsigned long eport_pcsc_dword;
typedef eport_pcsc_long eport_pcsc_context;
typedef eport_pcsc_long eport_pcsc_handle;

typedef struct eport_pcsc_io_request {
    unsigned long protocol;
    unsigned long length;
} eport_pcsc_io_request;

typedef eport_pcsc_long eport_pcsc_establish_context_fn(
    eport_pcsc_dword scope,
    const void *reserved1,
    const void *reserved2,
    eport_pcsc_context *context);
typedef eport_pcsc_long eport_pcsc_release_context_fn(eport_pcsc_context context);
typedef eport_pcsc_long eport_pcsc_list_readers_fn(
    eport_pcsc_context context,
    const char *groups,
    char *readers,
    eport_pcsc_dword *readers_length);
typedef eport_pcsc_long eport_pcsc_connect_fn(
    eport_pcsc_context context,
    const char *reader_name,
    eport_pcsc_dword share_mode,
    eport_pcsc_dword preferred_protocols,
    eport_pcsc_handle *card,
    eport_pcsc_dword *protocol);
typedef eport_pcsc_long eport_pcsc_transmit_fn(
    eport_pcsc_handle card,
    const eport_pcsc_io_request *send_pci,
    const uint8_t *command,
    eport_pcsc_dword command_length,
    eport_pcsc_io_request *receive_pci,
    uint8_t *response,
    eport_pcsc_dword *response_length);
typedef eport_pcsc_long eport_pcsc_disconnect_fn(
    eport_pcsc_handle card, eport_pcsc_dword disposition);

typedef struct eport_pcsc_api {
    void *library;
    eport_pcsc_establish_context_fn *establish_context;
    eport_pcsc_release_context_fn *release_context;
    eport_pcsc_list_readers_fn *list_readers;
    eport_pcsc_connect_fn *connect;
    eport_pcsc_transmit_fn *transmit;
    eport_pcsc_disconnect_fn *disconnect;
} eport_pcsc_api;

struct eport_pcsc_platform_device {
    eport_pcsc_api api;
    eport_pcsc_context context;
    eport_pcsc_handle card;
    eport_pcsc_dword protocol;
};

/* dlsym hands back a data pointer, which is copied into the function pointer
   slot rather than cast, so the code builds on toolchains that diagnose
   pointer conversions. */
static eportskf_result eport_pcsc_load_symbol(
    void *library, const char *name, void *target, size_t target_size)
{
    void *symbol;

    if (target_size != sizeof(symbol)) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    symbol = dlsym(library, name);
    if (symbol == NULL) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    memcpy(target, &symbol, sizeof(symbol));
    return EPORTSKF_SUCCESS;
}

/* The six entry points form one unit: a service that lacks any of them cannot
   run a session, so a partial load is discarded instead of being reported as
   available. */
static eportskf_result eport_pcsc_load_api(eport_pcsc_api *api)
{
    memset(api, 0, sizeof(*api));
    api->library = dlopen("libpcsclite.so.1", RTLD_NOW | RTLD_LOCAL);
    if (api->library == NULL) {
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    if (eport_pcsc_load_symbol(api->library, "SCardEstablishContext",
            &api->establish_context, sizeof(api->establish_context)) != EPORTSKF_SUCCESS
        || eport_pcsc_load_symbol(api->library, "SCardReleaseContext",
            &api->release_context, sizeof(api->release_context)) != EPORTSKF_SUCCESS
        || eport_pcsc_load_symbol(api->library, "SCardListReaders",
            &api->list_readers, sizeof(api->list_readers)) != EPORTSKF_SUCCESS
        || eport_pcsc_load_symbol(api->library, "SCardConnect",
            &api->connect, sizeof(api->connect)) != EPORTSKF_SUCCESS
        || eport_pcsc_load_symbol(api->library, "SCardTransmit",
            &api->transmit, sizeof(api->transmit)) != EPORTSKF_SUCCESS
        || eport_pcsc_load_symbol(api->library, "SCardDisconnect",
            &api->disconnect, sizeof(api->disconnect)) != EPORTSKF_SUCCESS) {
        dlclose(api->library);
        memset(api, 0, sizeof(*api));
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    return EPORTSKF_SUCCESS;
}

static void eport_pcsc_unload_api(eport_pcsc_api *api)
{
    if (api->library != NULL) {
        dlclose(api->library);
        api->library = NULL;
    }
}

/* The first list_readers call reports the buffer size and the second returns
   the double-NUL-terminated names, which is how the service exposes a
   variable-length list. */
eportskf_result eport_pcsc_platform_enumerate(eport_name_visitor visitor, void *context)
{
    static const char *all_readers = NULL;
    eport_pcsc_api api;
    eport_pcsc_context smart_card_context = 0;
    char *readers = NULL;
    char *reader;
    eport_pcsc_dword readers_capacity = 0;
    eport_pcsc_dword readers_length;
    size_t remaining;
    eport_pcsc_long status;
    eportskf_result result;

    if (visitor == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    result = eport_pcsc_load_api(&api);
    if (result != EPORTSKF_SUCCESS) {
        return result;
    }
    status = api.establish_context(
        EPORT_PCSC_SCOPE_SYSTEM, NULL, NULL, &smart_card_context);
    if (status != 0) {
        eport_pcsc_unload_api(&api);
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    result = EPORTSKF_SUCCESS;
    status = api.list_readers(smart_card_context, all_readers, NULL, &readers_capacity);
    if (status == EPORT_PCSC_NO_READERS_AVAILABLE) {
        goto cleanup;
    }
    if (status != 0) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
        goto cleanup;
    }
    if (readers_capacity <= 1) {
        goto cleanup;
    }

    readers = malloc(readers_capacity);
    if (readers == NULL) {
        result = EPORTSKF_FAILURE;
        goto cleanup;
    }
    readers_length = readers_capacity;
    status = api.list_readers(smart_card_context, all_readers, readers, &readers_length);
    if (status == EPORT_PCSC_NO_READERS_AVAILABLE) {
        goto cleanup;
    }
    if (status != 0) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
        goto cleanup;
    }
    if (readers_length > readers_capacity) {
        result = EPORTSKF_FAILURE;
        goto cleanup;
    }

    reader = readers;
    remaining = readers_length;
    while (remaining > 0 && *reader != '\0') {
        char *terminator = memchr(reader, '\0', remaining);
        size_t consumed;

        if (terminator == NULL) {
            result = EPORTSKF_FAILURE;
            goto cleanup;
        }
        result = visitor(reader, context);
        if (result != EPORTSKF_SUCCESS) {
            goto cleanup;
        }

        consumed = (size_t)(terminator - reader) + 1;
        reader += consumed;
        remaining -= consumed;
    }

cleanup:
    free(readers);
    if (api.release_context(smart_card_context) != 0 && result == EPORTSKF_SUCCESS) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
    }
    eport_pcsc_unload_api(&api);
    return result;
}

eportskf_result eport_pcsc_platform_open(
    const char *reader_name, eport_pcsc_platform_device **out_device)
{
    eport_pcsc_platform_device *device;
    eport_pcsc_long status;
    eportskf_result result;

    if (out_device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    *out_device = NULL;
    if (reader_name == NULL || reader_name[0] == '\0') {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }

    device = calloc(1, sizeof(*device));
    if (device == NULL) {
        return EPORTSKF_FAILURE;
    }
    result = eport_pcsc_load_api(&device->api);
    if (result != EPORTSKF_SUCCESS) {
        free(device);
        return result;
    }

    status = device->api.establish_context(
        EPORT_PCSC_SCOPE_SYSTEM, NULL, NULL, &device->context);
    if (status != 0) {
        eport_pcsc_unload_api(&device->api);
        free(device);
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }
    status = device->api.connect(
        device->context,
        reader_name,
        EPORT_PCSC_SHARE_SHARED,
        EPORT_PCSC_PROTOCOL_T0 | EPORT_PCSC_PROTOCOL_T1,
        &device->card,
        &device->protocol);
    if (status != 0) {
        device->api.release_context(device->context);
        eport_pcsc_unload_api(&device->api);
        free(device);
        return EPORTSKF_DEVICE_UNAVAILABLE;
    }

    *out_device = device;
    return EPORTSKF_SUCCESS;
}

/* The service takes 32-bit lengths, so the sizes are narrowed and widened back
   instead of being truncated silently. */
eportskf_result eport_pcsc_platform_transmit(
    eport_pcsc_platform_device *device,
    const uint8_t *command,
    size_t command_length,
    uint8_t *response,
    size_t *response_length)
{
    eport_pcsc_io_request send_pci;
    size_t response_capacity;
    eport_pcsc_dword command_size;
    eport_pcsc_dword received_length;
    eport_pcsc_long status;

    if (device == NULL || command == NULL || response == NULL || response_length == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    response_capacity = *response_length;
    command_size = (eport_pcsc_dword)command_length;
    received_length = (eport_pcsc_dword)response_capacity;
    if ((size_t)command_size != command_length
        || (size_t)received_length != response_capacity) {
        *response_length = 0;
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }

    send_pci.protocol = device->protocol;
    send_pci.length = sizeof(send_pci);
    status = device->api.transmit(
        device->card,
        &send_pci,
        command,
        command_size,
        NULL,
        response,
        &received_length);
    if (status != 0) {
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

eportskf_result eport_pcsc_platform_close(eport_pcsc_platform_device *device)
{
    eportskf_result result = EPORTSKF_SUCCESS;

    if (device == NULL) {
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    if (device->api.disconnect(device->card, EPORT_PCSC_UNPOWER_CARD) != 0) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
    }
    if (device->api.release_context(device->context) != 0) {
        result = EPORTSKF_DEVICE_UNAVAILABLE;
    }
    eport_pcsc_unload_api(&device->api);
    free(device);
    return result;
}
