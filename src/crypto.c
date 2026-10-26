/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 Jiaowei <wei.jiao@guanwu.com> */

/* SHA1, SM3, SM2 digest preparation, and SM4 block encryption.
 *
 * Both hashes are incremental and retain only fixed state, which is what lets
 * the API sign messages of any length. The SM2 and SM4 helpers cover the two
 * card operations that need them: seeding a hash with ZA before absorbing a
 * message, and encrypting the single PIN block.
 */
#include "crypto.h"

#include <string.h>

static uint32_t eport_load32(const uint8_t bytes[4])
{
    return ((uint32_t)bytes[0] << 24) |
        ((uint32_t)bytes[1] << 16) |
        ((uint32_t)bytes[2] << 8) |
        (uint32_t)bytes[3];
}

static void eport_store32(uint8_t bytes[4], uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static void eport_store64(uint8_t bytes[8], uint64_t value)
{
    unsigned int index;

    for (index = 0; index < 8; ++index) {
        bytes[index] = (uint8_t)(value >> (56 - index * 8));
    }
}

static uint32_t eport_rotate_left(uint32_t value, unsigned int distance)
{
    distance &= 31U;
    if (distance == 0) {
        return value;
    }
    return (value << distance) | (value >> (32U - distance));
}

static void eport_sha1_compress(eport_sha1 *hash, const uint8_t block[64])
{
    uint32_t words[80];
    uint32_t a = hash->state[0];
    uint32_t b = hash->state[1];
    uint32_t c = hash->state[2];
    uint32_t d = hash->state[3];
    uint32_t e = hash->state[4];
    unsigned int index;

    for (index = 0; index < 16; ++index) {
        words[index] = eport_load32(block + index * 4);
    }
    for (index = 16; index < 80; ++index) {
        words[index] = eport_rotate_left(
            words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16], 1);
    }
    for (index = 0; index < 80; ++index) {
        uint32_t function;
        uint32_t constant;
        uint32_t temporary;

        if (index < 20) {
            function = (b & c) | (~b & d);
            constant = UINT32_C(0x5a827999);
        } else if (index < 40) {
            function = b ^ c ^ d;
            constant = UINT32_C(0x6ed9eba1);
        } else if (index < 60) {
            function = (b & c) | (b & d) | (c & d);
            constant = UINT32_C(0x8f1bbcdc);
        } else {
            function = b ^ c ^ d;
            constant = UINT32_C(0xca62c1d6);
        }
        temporary = eport_rotate_left(a, 5) + function + e + constant + words[index];
        e = d;
        d = c;
        c = eport_rotate_left(b, 30);
        b = a;
        a = temporary;
    }
    hash->state[0] += a;
    hash->state[1] += b;
    hash->state[2] += c;
    hash->state[3] += d;
    hash->state[4] += e;
}

void eport_sha1_init(eport_sha1 *hash)
{
    hash->state[0] = UINT32_C(0x67452301);
    hash->state[1] = UINT32_C(0xefcdab89);
    hash->state[2] = UINT32_C(0x98badcfe);
    hash->state[3] = UINT32_C(0x10325476);
    hash->state[4] = UINT32_C(0xc3d2e1f0);
    hash->total_bytes = 0;
    hash->block_length = 0;
}

void eport_sha1_update(eport_sha1 *hash, const void *data, size_t length)
{
    const uint8_t *input = data;

    hash->total_bytes += length;
    if (hash->block_length != 0) {
        size_t available = 64 - hash->block_length;
        size_t take = length < available ? length : available;

        if (take != 0) {
            memcpy(hash->block + hash->block_length, input, take);
            hash->block_length += take;
            input += take;
            length -= take;
        }
        if (hash->block_length == 64) {
            eport_sha1_compress(hash, hash->block);
            hash->block_length = 0;
        }
    }
    while (length >= 64) {
        eport_sha1_compress(hash, input);
        input += 64;
        length -= 64;
    }
    if (length != 0) {
        memcpy(hash->block, input, length);
        hash->block_length = length;
    }
}

void eport_sha1_final(eport_sha1 *hash, uint8_t digest[EPORT_SHA1_DIGEST_SIZE])
{
    uint64_t total_bits = hash->total_bytes * UINT64_C(8);
    size_t used = hash->block_length;
    unsigned int index;

    hash->block[used++] = 0x80;
    if (used > 56) {
        memset(hash->block + used, 0, 64 - used);
        eport_sha1_compress(hash, hash->block);
        used = 0;
    }
    memset(hash->block + used, 0, 56 - used);
    eport_store64(hash->block + 56, total_bits);
    eport_sha1_compress(hash, hash->block);
    for (index = 0; index < 5; ++index) {
        eport_store32(digest + index * 4, hash->state[index]);
    }
}

static uint32_t eport_sm3_p0(uint32_t value)
{
    return value ^ eport_rotate_left(value, 9) ^ eport_rotate_left(value, 17);
}

static uint32_t eport_sm3_p1(uint32_t value)
{
    return value ^ eport_rotate_left(value, 15) ^ eport_rotate_left(value, 23);
}

static void eport_sm3_compress(eport_sm3 *hash, const uint8_t block[64])
{
    uint32_t words[68];
    uint32_t a = hash->state[0];
    uint32_t b = hash->state[1];
    uint32_t c = hash->state[2];
    uint32_t d = hash->state[3];
    uint32_t e = hash->state[4];
    uint32_t f = hash->state[5];
    uint32_t g = hash->state[6];
    uint32_t h = hash->state[7];
    unsigned int index;

    for (index = 0; index < 16; ++index) {
        words[index] = eport_load32(block + index * 4);
    }
    for (index = 16; index < 68; ++index) {
        words[index] = eport_sm3_p1(
            words[index - 16] ^ words[index - 9] ^ eport_rotate_left(words[index - 3], 15)) ^
            eport_rotate_left(words[index - 13], 7) ^ words[index - 6];
    }
    for (index = 0; index < 64; ++index) {
        uint32_t constant = index < 16 ? UINT32_C(0x79cc4519) : UINT32_C(0x7a879d8a);
        uint32_t ss1 = eport_rotate_left(
            eport_rotate_left(a, 12) + e + eport_rotate_left(constant, index), 7);
        uint32_t ss2 = ss1 ^ eport_rotate_left(a, 12);
        uint32_t ff = index < 16 ? a ^ b ^ c : (a & b) | (a & c) | (b & c);
        uint32_t gg = index < 16 ? e ^ f ^ g : (e & f) | (~e & g);
        uint32_t tt1 = ff + d + ss2 + (words[index] ^ words[index + 4]);
        uint32_t tt2 = gg + h + ss1 + words[index];

        d = c;
        c = eport_rotate_left(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = eport_rotate_left(f, 19);
        f = e;
        e = eport_sm3_p0(tt2);
    }
    hash->state[0] ^= a;
    hash->state[1] ^= b;
    hash->state[2] ^= c;
    hash->state[3] ^= d;
    hash->state[4] ^= e;
    hash->state[5] ^= f;
    hash->state[6] ^= g;
    hash->state[7] ^= h;
}

void eport_sm3_init(eport_sm3 *hash)
{
    hash->state[0] = UINT32_C(0x7380166f);
    hash->state[1] = UINT32_C(0x4914b2b9);
    hash->state[2] = UINT32_C(0x172442d7);
    hash->state[3] = UINT32_C(0xda8a0600);
    hash->state[4] = UINT32_C(0xa96f30bc);
    hash->state[5] = UINT32_C(0x163138aa);
    hash->state[6] = UINT32_C(0xe38dee4d);
    hash->state[7] = UINT32_C(0xb0fb0e4e);
    hash->total_bytes = 0;
    hash->block_length = 0;
}

void eport_sm3_update(eport_sm3 *hash, const void *data, size_t length)
{
    const uint8_t *input = data;

    hash->total_bytes += length;
    if (hash->block_length != 0) {
        size_t available = 64 - hash->block_length;
        size_t take = length < available ? length : available;

        if (take != 0) {
            memcpy(hash->block + hash->block_length, input, take);
            hash->block_length += take;
            input += take;
            length -= take;
        }
        if (hash->block_length == 64) {
            eport_sm3_compress(hash, hash->block);
            hash->block_length = 0;
        }
    }
    while (length >= 64) {
        eport_sm3_compress(hash, input);
        input += 64;
        length -= 64;
    }
    if (length != 0) {
        memcpy(hash->block, input, length);
        hash->block_length = length;
    }
}

void eport_sm3_final(eport_sm3 *hash, uint8_t digest[EPORT_SM3_DIGEST_SIZE])
{
    uint64_t total_bits = hash->total_bytes * UINT64_C(8);
    size_t used = hash->block_length;
    unsigned int index;

    hash->block[used++] = 0x80;
    if (used > 56) {
        memset(hash->block + used, 0, 64 - used);
        eport_sm3_compress(hash, hash->block);
        used = 0;
    }
    memset(hash->block + used, 0, 56 - used);
    eport_store64(hash->block + 56, total_bits);
    eport_sm3_compress(hash, hash->block);
    for (index = 0; index < 8; ++index) {
        eport_store32(digest + index * 4, hash->state[index]);
    }
}

/* Seeds hash so that the message bytes appended afterwards complete
   SM3(ZA || message). ZA depends only on the fixed user identifier and the
   SM2 curve parameters in the literal below, plus the certificate public
   point, so the same seed serves every message from one device. */
void eport_sm2_digest_init(eport_sm3 *hash, const uint8_t public_key[64])
{
    static const uint8_t fixed_input[] = {
        0x00, 0x80,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
        0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34,
        0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7,
        0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92,
        0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93,
        0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19,
        0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94,
        0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1,
        0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7,
        0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c,
        0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
        0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
        0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0
    };
    eport_sm3 za_hash;
    uint8_t za[EPORT_SM3_DIGEST_SIZE];

    eport_sm3_init(&za_hash);
    eport_sm3_update(&za_hash, fixed_input, sizeof(fixed_input));
    eport_sm3_update(&za_hash, public_key, 64);
    eport_sm3_final(&za_hash, za);
    eport_sm3_init(hash);
    eport_sm3_update(hash, za, sizeof(za));
}

static const uint8_t eport_sm4_sbox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

static uint32_t eport_sm4_substitute(uint32_t value)
{
    return ((uint32_t)eport_sm4_sbox[(value >> 24) & 0xff] << 24) |
        ((uint32_t)eport_sm4_sbox[(value >> 16) & 0xff] << 16) |
        ((uint32_t)eport_sm4_sbox[(value >> 8) & 0xff] << 8) |
        (uint32_t)eport_sm4_sbox[value & 0xff];
}

static uint32_t eport_sm4_round_transform(uint32_t value)
{
    uint32_t substituted = eport_sm4_substitute(value);

    return substituted ^ eport_rotate_left(substituted, 2) ^
        eport_rotate_left(substituted, 10) ^ eport_rotate_left(substituted, 18) ^
        eport_rotate_left(substituted, 24);
}

static uint32_t eport_sm4_key_transform(uint32_t value)
{
    uint32_t substituted = eport_sm4_substitute(value);

    return substituted ^ eport_rotate_left(substituted, 13) ^ eport_rotate_left(substituted, 23);
}

/* Encrypts one 16-byte block in ECB mode without padding, which is exactly the
   single block a PIN verification sends. */
void eport_sm4_encrypt_block(const uint8_t key[16], const uint8_t input[16], uint8_t output[16])
{
    static const uint32_t family_key[4] = {
        UINT32_C(0xa3b1bac6), UINT32_C(0x56aa3350),
        UINT32_C(0x677d9197), UINT32_C(0xb27022dc)
    };
    static const uint32_t constants[32] = {
        UINT32_C(0x00070e15), UINT32_C(0x1c232a31), UINT32_C(0x383f464d), UINT32_C(0x545b6269),
        UINT32_C(0x70777e85), UINT32_C(0x8c939aa1), UINT32_C(0xa8afb6bd), UINT32_C(0xc4cbd2d9),
        UINT32_C(0xe0e7eef5), UINT32_C(0xfc030a11), UINT32_C(0x181f262d), UINT32_C(0x343b4249),
        UINT32_C(0x50575e65), UINT32_C(0x6c737a81), UINT32_C(0x888f969d), UINT32_C(0xa4abb2b9),
        UINT32_C(0xc0c7ced5), UINT32_C(0xdce3eaf1), UINT32_C(0xf8ff060d), UINT32_C(0x141b2229),
        UINT32_C(0x30373e45), UINT32_C(0x4c535a61), UINT32_C(0x686f767d), UINT32_C(0x848b9299),
        UINT32_C(0xa0a7aeb5), UINT32_C(0xbcc3cad1), UINT32_C(0xd8dfe6ed), UINT32_C(0xf4fb0209),
        UINT32_C(0x10171e25), UINT32_C(0x2c333a41), UINT32_C(0x484f565d), UINT32_C(0x646b7279)
    };
    uint32_t words[36];
    uint32_t round_keys[32];
    uint32_t state[36];
    unsigned int index;

    for (index = 0; index < 4; ++index) {
        words[index] = eport_load32(key + index * 4) ^ family_key[index];
        state[index] = eport_load32(input + index * 4);
    }
    for (index = 0; index < 32; ++index) {
        words[index + 4] = words[index] ^ eport_sm4_key_transform(
            words[index + 1] ^ words[index + 2] ^ words[index + 3] ^ constants[index]);
        round_keys[index] = words[index + 4];
    }
    for (index = 0; index < 32; ++index) {
        state[index + 4] = state[index] ^ eport_sm4_round_transform(
            state[index + 1] ^ state[index + 2] ^ state[index + 3] ^ round_keys[index]);
    }
    for (index = 0; index < 4; ++index) {
        eport_store32(output + index * 4, state[35 - index]);
    }
}
