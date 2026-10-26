/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* Incremental hashes, ZA construction, and PIN-block encryption.
 *
 * A hash keeps only its fixed state and at most one partial 64-byte block, so
 * a streaming signer never buffers the message. final consumes that state;
 * init must run again before hashing another message.
 */
#ifndef EPORTSKF_CRYPTO_H
#define EPORTSKF_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define EPORT_SHA1_DIGEST_SIZE 20
#define EPORT_SM3_DIGEST_SIZE 32

typedef struct eport_sha1 {
    uint32_t state[5];
    uint64_t total_bytes;
    uint8_t block[64];
    size_t block_length;
} eport_sha1;

typedef struct eport_sm3 {
    uint32_t state[8];
    uint64_t total_bytes;
    uint8_t block[64];
    size_t block_length;
} eport_sm3;

void eport_sha1_init(eport_sha1 *hash);
void eport_sha1_update(eport_sha1 *hash, const void *data, size_t length);
void eport_sha1_final(eport_sha1 *hash, uint8_t digest[EPORT_SHA1_DIGEST_SIZE]);

void eport_sm3_init(eport_sm3 *hash);
void eport_sm3_update(eport_sm3 *hash, const void *data, size_t length);
void eport_sm3_final(eport_sm3 *hash, uint8_t digest[EPORT_SM3_DIGEST_SIZE]);

/* public_key is the certificate point x||y, 32 bytes each. */
void eport_sm2_digest_init(eport_sm3 *hash, const uint8_t public_key[64]);

/* One 16-byte block, ECB mode, no padding. */
void eport_sm4_encrypt_block(const uint8_t key[16], const uint8_t input[16], uint8_t output[16]);

#endif
