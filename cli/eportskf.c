/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* Command-line front end.
 *
 * The tool is a thin client of the public API: it selects a device, prints the
 * identity, reads the PIN from standard input, signs command-line text or a
 * file, and prints the signature in hexadecimal and Base64. Exit status is 0
 * for success, 2 for a command usage error, and 1 for a runtime failure.
 */
#include "eportskf.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <shellapi.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#define CLI_SUCCESS 0
#define CLI_RUNTIME_FAILURE 1
#define CLI_USAGE_ERROR 2
#define CLI_FILE_CHUNK_SIZE 8192

/* Zeroes a secret buffer in a way the optimizer cannot remove. */
static void cli_wipe(void *memory, size_t length)
{
    volatile unsigned char *bytes = memory;

    while (length-- != 0) {
        *bytes++ = 0;
    }
}

static int cli_stdin_is_interactive(void)
{
#ifdef _WIN32
    return _isatty(_fileno(stdin));
#else
    return isatty(STDIN_FILENO);
#endif
}

static void cli_usage(FILE *stream, const char *program)
{
    fprintf(stream,
        "Usage:\n"
        "  %s list\n"
        "  %s identity [DEVICE]\n"
        "  %s sign [--device DEVICE] (--text TEXT | --file PATH)\n",
        program, program, program);
}

static void cli_print_identity(const eportskf_identity *identity)
{
    printf("Certificate ID: %s\n", identity->cert_id);
    printf("Device ID: %s\n", identity->device_id);
}

static int cli_runtime_error(eportskf_result result)
{
    fprintf(stderr, "Error: %s\n", eportskf_result_description(result));
    return CLI_RUNTIME_FAILURE;
}

/* Resolves the device name for a command. An omitted name is enumerated and
   accepted only when exactly one device is present; the returned name then
   points into list, so the caller frees the list exactly when must_free is
   set. */
static int cli_select_name(
    const char *requested,
    eportskf_device_list *list,
    const char **name,
    int *must_free)
{
    eportskf_result result;

    *list = (eportskf_device_list){0};
    *must_free = 0;
    if (requested != NULL) {
        *name = requested;
        return CLI_SUCCESS;
    }
    result = eportskf_enumerate(list);
    if (result != EPORTSKF_SUCCESS) {
        return cli_runtime_error(result);
    }
    *must_free = 1;
    if (list->count == 0) {
        fprintf(stderr, "Error: Device unavailable\n");
        return CLI_RUNTIME_FAILURE;
    }
    if (list->count != 1) {
        size_t index;

        fprintf(stderr, "More than one device is present; select one by name:\n");
        for (index = 0; index < list->count; ++index) {
            fprintf(stderr, "  %s\n", list->items[index].name);
        }
        return CLI_USAGE_ERROR;
    }
    *name = list->items[0].name;
    return CLI_SUCCESS;
}

static int cli_list(void)
{
    eportskf_device_list list = {0};
    eportskf_result result = eportskf_enumerate(&list);
    size_t index;

    if (result != EPORTSKF_SUCCESS) {
        return cli_runtime_error(result);
    }
    if (list.count == 0) {
        printf("No devices found.\n");
    }
    for (index = 0; index < list.count; ++index) {
        if (index != 0) {
            printf("\n");
        }
        printf("Device: %s\n", list.items[index].name);
        cli_print_identity(&list.items[index].identity);
    }
    eportskf_free_device_list(&list);
    return CLI_SUCCESS;
}

static int cli_identity(const char *requested)
{
    eportskf_device_list list;
    eportskf_device *device = NULL;
    eportskf_identity identity = {0};
    const char *name = NULL;
    int must_free;
    int status = cli_select_name(requested, &list, &name, &must_free);
    eportskf_result result;

    if (status != CLI_SUCCESS) {
        if (must_free) {
            eportskf_free_device_list(&list);
        }
        return status;
    }
    result = eportskf_open(name, &device);
    if (result == EPORTSKF_SUCCESS) {
        printf("Device: %s\n", name);
        result = eportskf_read_identity(device, &identity);
    }
    if (result == EPORTSKF_SUCCESS) {
        cli_print_identity(&identity);
        eportskf_free_identity(&identity);
    } else {
        status = cli_runtime_error(result);
    }
    if (device != NULL) {
        result = eportskf_close(device);
        if (status == CLI_SUCCESS && result != EPORTSKF_SUCCESS) {
            status = cli_runtime_error(result);
        }
    }
    if (must_free) {
        eportskf_free_device_list(&list);
    }
    return status;
}

#ifdef _WIN32
typedef struct cli_input_mode {
    HANDLE handle;
    DWORD mode;
    int changed;
} cli_input_mode;
#else
typedef struct cli_input_mode {
    struct termios mode;
    int changed;
} cli_input_mode;
#endif

static void cli_disable_echo(cli_input_mode *input)
{
    memset(input, 0, sizeof(*input));
#ifdef _WIN32
    input->handle = GetStdHandle(STD_INPUT_HANDLE);
    if (input->handle != INVALID_HANDLE_VALUE && GetConsoleMode(input->handle, &input->mode)) {
        if (SetConsoleMode(input->handle, input->mode & ~ENABLE_ECHO_INPUT)) {
            input->changed = 1;
        }
    }
#else
    if (tcgetattr(STDIN_FILENO, &input->mode) == 0) {
        struct termios hidden = input->mode;
        hidden.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0) {
            input->changed = 1;
        }
    }
#endif
}

static void cli_restore_echo(const cli_input_mode *input)
{
#ifdef _WIN32
    if (input->changed) {
        (void)SetConsoleMode(input->handle, input->mode);
    }
#else
    if (input->changed) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &input->mode);
    }
#endif
}

/* Reads the PIN from one line of standard input so it never appears in the
   process command line. Non-interactive input is accepted for scripts;
   interactive entry also hides the echo. Exactly eight characters are
   required, and the local copy is wiped once the PIN is copied out. */
static eportskf_result cli_read_pin(char pin[EPORTSKF_PIN_SIZE + 1])
{
    cli_input_mode input;
    unsigned char buffer[EPORTSKF_PIN_SIZE + 1];
    size_t length = 0;
    int interactive = cli_stdin_is_interactive();
    int character;

    if (interactive) {
        fprintf(stderr, "PIN: ");
        fflush(stderr);
        cli_disable_echo(&input);
    }
    while ((character = fgetc(stdin)) != EOF && character != '\n' && character != '\r') {
        if (length < sizeof(buffer)) {
            buffer[length] = (unsigned char)character;
        }
        ++length;
    }
    if (interactive) {
        cli_restore_echo(&input);
        fprintf(stderr, "\n");
    }
    if (ferror(stdin)) {
        cli_wipe(buffer, sizeof(buffer));
        return EPORTSKF_FAILURE;
    }
    if (length != EPORTSKF_PIN_SIZE) {
        cli_wipe(buffer, sizeof(buffer));
        return EPORTSKF_UNUSABLE_ARGUMENT;
    }
    memcpy(pin, buffer, EPORTSKF_PIN_SIZE);
    pin[EPORTSKF_PIN_SIZE] = '\0';
    cli_wipe(buffer, sizeof(buffer));
    return EPORTSKF_SUCCESS;
}

/* Windows command-line paths are UTF-8, so the file has to be opened through
   the wide-character call; other platforms pass the path through unchanged. */
static FILE *cli_open_file(const char *path)
{
#ifdef _WIN32
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    wchar_t *wide_path;
    FILE *file;

    if (length <= 0) {
        errno = EINVAL;
        return NULL;
    }
    wide_path = malloc((size_t)length * sizeof(*wide_path));
    if (wide_path == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide_path, length) != length) {
        free(wide_path);
        errno = EINVAL;
        return NULL;
    }
    file = _wfopen(wide_path, L"rb");
    free(wide_path);
    return file;
#else
    return fopen(path, "rb");
#endif
}

static const char *cli_algorithm_name(eportskf_algorithm algorithm)
{
    switch (algorithm) {
    case EPORTSKF_ALGORITHM_SM2_SM3:
        return "SM2-SM3";
    case EPORTSKF_ALGORITHM_RSA_SHA1:
        return "RSA-SHA1";
    default:
        return "Unknown";
    }
}

/* The hexadecimal and Base64 forms are printed from the same buffer without an
   intermediate copy, so a 128-byte signature still stays on one output line. */
static void cli_print_signature(const eportskf_signature *signature)
{
    static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t index;

    printf("Algorithm: %s\n", cli_algorithm_name(signature->algorithm));
    printf("Signature length: %lu\n", (unsigned long)signature->length);
    printf("Signature (hex): ");
    for (index = 0; index < signature->length; ++index) {
        printf("%02x", (unsigned int)signature->bytes[index]);
    }
    printf("\nSignature (base64): ");
    for (index = 0; index < signature->length; index += 3) {
        size_t remaining = signature->length - index;
        uint32_t value = (uint32_t)signature->bytes[index] << 16;

        if (remaining > 1) {
            value |= (uint32_t)signature->bytes[index + 1] << 8;
        }
        if (remaining > 2) {
            value |= signature->bytes[index + 2];
        }
        putchar(base64[(value >> 18) & 63]);
        putchar(base64[(value >> 12) & 63]);
        putchar(remaining > 1 ? base64[(value >> 6) & 63] : '=');
        putchar(remaining > 2 ? base64[value & 63] : '=');
    }
    printf("\n");
}

/* Hashes the file in bounded chunks, so memory use does not grow with the
   message. Any read or update failure abandons the streaming signature before
   it reaches the card. */
static eportskf_result cli_sign_file(eportskf_device *device, const char *path)
{
    FILE *file = cli_open_file(path);
    uint8_t buffer[CLI_FILE_CHUNK_SIZE];
    size_t count;
    eportskf_signature signature;
    eportskf_result result;

    if (file == NULL) {
        fprintf(stderr, "Cannot open file '%s': %s\n", path, strerror(errno));
        return EPORTSKF_FAILURE;
    }
    result = eportskf_sign_start(device);
    while (result == EPORTSKF_SUCCESS && (count = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        result = eportskf_sign_update(device, buffer, count);
    }
    if (result == EPORTSKF_SUCCESS && ferror(file)) {
        fprintf(stderr, "Cannot read file '%s': %s\n", path, strerror(errno));
        result = EPORTSKF_FAILURE;
    }
    if (fclose(file) != 0 && result == EPORTSKF_SUCCESS) {
        result = EPORTSKF_FAILURE;
    }
    if (result != EPORTSKF_SUCCESS) {
        (void)eportskf_sign_abort(device);
        return result;
    }
    result = eportskf_sign_finish(device, &signature);
    if (result == EPORTSKF_SUCCESS) {
        cli_print_signature(&signature);
    }
    return result;
}

/* A failed identity read is printed but does not stop the command, because
   signing retries the certificate exchange and may succeed. */
static int cli_sign(const char *requested, const char *text, const char *path)
{
    eportskf_device_list list;
    eportskf_device *device = NULL;
    eportskf_identity identity = {0};
    eportskf_signature signature;
    const char *name = NULL;
    char pin[EPORTSKF_PIN_SIZE + 1];
    int must_free;
    int status = cli_select_name(requested, &list, &name, &must_free);
    eportskf_result result;

    if (status != CLI_SUCCESS) {
        if (must_free) {
            eportskf_free_device_list(&list);
        }
        return status;
    }
    result = eportskf_open(name, &device);
    if (result != EPORTSKF_SUCCESS) {
        status = cli_runtime_error(result);
        goto cleanup;
    }
    printf("Device: %s\n", name);
    result = eportskf_read_identity(device, &identity);
    if (result == EPORTSKF_SUCCESS) {
        cli_print_identity(&identity);
        eportskf_free_identity(&identity);
    } else {
        printf("Identity: %s\n", eportskf_result_description(result));
    }
    result = cli_read_pin(pin);
    if (result != EPORTSKF_SUCCESS) {
        status = cli_runtime_error(result);
        goto cleanup;
    }
    result = eportskf_verify_pin(device, pin);
    cli_wipe(pin, sizeof(pin));
    printf("PIN: %s\n", result == EPORTSKF_SUCCESS ? "verified" : eportskf_result_description(result));
    if (result != EPORTSKF_SUCCESS) {
        status = CLI_RUNTIME_FAILURE;
        goto cleanup;
    }
    if (text != NULL) {
        result = eportskf_sign(device, text, strlen(text), &signature);
        if (result == EPORTSKF_SUCCESS) {
            cli_print_signature(&signature);
        }
    } else {
        result = cli_sign_file(device, path);
    }
    if (result != EPORTSKF_SUCCESS) {
        status = cli_runtime_error(result);
    }

cleanup:
    if (device != NULL) {
        result = eportskf_close(device);
        if (status == CLI_SUCCESS && result != EPORTSKF_SUCCESS) {
            status = cli_runtime_error(result);
        }
    }
    if (must_free) {
        eportskf_free_device_list(&list);
    }
    return status;
}

static int cli_parse_sign(int argc, char **argv)
{
    const char *device = NULL;
    const char *text = NULL;
    const char *path = NULL;
    int index;

    for (index = 2; index < argc; ++index) {
        if (index + 1 >= argc) {
            cli_usage(stderr, argv[0]);
            return CLI_USAGE_ERROR;
        }
        if (strcmp(argv[index], "--device") == 0 && device == NULL) {
            device = argv[++index];
        } else if (strcmp(argv[index], "--text") == 0 && text == NULL && path == NULL) {
            text = argv[++index];
        } else if (strcmp(argv[index], "--file") == 0 && path == NULL && text == NULL) {
            path = argv[++index];
        } else {
            cli_usage(stderr, argv[0]);
            return CLI_USAGE_ERROR;
        }
    }
    if ((text == NULL) == (path == NULL)) {
        cli_usage(stderr, argv[0]);
        return CLI_USAGE_ERROR;
    }
    return cli_sign(device, text, path);
}

static int cli_run(int argc, char **argv)
{
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        cli_usage(stdout, argv[0]);
        return CLI_SUCCESS;
    }
    if (argc == 2 && strcmp(argv[1], "list") == 0) {
        return cli_list();
    }
    if ((argc == 2 || argc == 3) && strcmp(argv[1], "identity") == 0) {
        return cli_identity(argc == 3 ? argv[2] : NULL);
    }
    if (argc >= 3 && strcmp(argv[1], "sign") == 0) {
        return cli_parse_sign(argc, argv);
    }
    cli_usage(stderr, argv[0]);
    return CLI_USAGE_ERROR;
}

#ifdef _WIN32
static char *cli_utf8_from_wide(const wchar_t *wide)
{
    int length = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    char *text;

    if (length <= 0) {
        return NULL;
    }
    text = malloc((size_t)length);
    if (text != NULL && WideCharToMultiByte(CP_UTF8, 0, wide, -1, text, length, NULL, NULL) != length) {
        free(text);
        text = NULL;
    }
    return text;
}

int main(void)
{
    LPWSTR *wide_argv;
    char **argv = NULL;
    int argc = 0;
    int index;
    int status = CLI_RUNTIME_FAILURE;
    UINT previous_code_page = GetConsoleOutputCP();
    int restore_code_page = SetConsoleOutputCP(CP_UTF8) != 0;

    /* Windows supplies UTF-16 arguments and the tool works in UTF-8; the
       console output code page is switched so printed text is readable and is
       restored before the process exits. */
    wide_argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (wide_argv == NULL) {
        fprintf(stderr, "Error: Failure\n");
        goto cleanup;
    }
    argv = calloc((size_t)argc + 1, sizeof(*argv));
    if (argv == NULL) {
        fprintf(stderr, "Error: Failure\n");
        goto cleanup;
    }
    for (index = 0; index < argc; ++index) {
        argv[index] = cli_utf8_from_wide(wide_argv[index]);
        if (argv[index] == NULL) {
            fprintf(stderr, "Error: Failure\n");
            goto cleanup;
        }
    }
    status = cli_run(argc, argv);

cleanup:
    if (argv != NULL) {
        for (index = 0; index < argc; ++index) {
            free(argv[index]);
        }
        free(argv);
    }
    if (wide_argv != NULL) {
        LocalFree(wide_argv);
    }
    if (restore_code_page) {
        (void)SetConsoleOutputCP(previous_code_page);
    }
    return status;
}
#else
int main(int argc, char **argv)
{
    return cli_run(argc, argv);
}
#endif
