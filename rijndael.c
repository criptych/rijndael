#include "rijndael.h"

#include <stdlib.h>
#include <stdio.h>

#ifndef NDEBUG
# define TRACE(...) do { \
    fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
    fprintf(stderr, ##__VA_ARGS__); \
    fputc('\n', stderr); \
} while(0)

# define PRINT(...) do {\
    fprintf(stderr, ##__VA_ARGS__); \
    fputc('\n', stderr); \
} while(0)

# define PRINT_BLOCK(blk, ...) do { \
    fprintf(stderr, ##__VA_ARGS__); \
    for (size_t n = 0; n < 16; ++n) { \
        fprintf(stderr, " %02x", ((uint8_t*)blk)[n]); \
    } \
    fputc('\n', stderr); \
} while(0)

#else
# define TRACE(...)
# define PRINT(...)
# define PRINT_BLOCK(...)
#endif

#define SHOW_ROUNDS

/* forward S-box */
static const uint8_t fsbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* reverse S-box */
static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

static uint8_t galois(uint8_t a, uint8_t b) {
    uint8_t n = 0;
    for (uint8_t i = 0; i < 8; ++i) {
        n ^= (a & 1) * b;
        b = (b << 1) ^ ((b >> 7) * 0x1b);
        a >>= 1;
    }
    return n;
}

static inline uint32_t ror32(uint32_t n, size_t bits) {
    return (n >> bits) | (n << (32 - bits));
}

static void rijndael_init_tables() {
    /* TODO calculate tables */
}

static void rijndael_subbytes(void *block, size_t block_size, const uint8_t *sbox) {
    uint8_t *bytes = (uint8_t*)block;
    size_t count = block_size * 4, i;
    for (i = 0; i < count; ++i) {
        bytes[i] = sbox[bytes[i]];
    }
}

static void rijndael_shiftrows(void *block, size_t block_size) {
    uint8_t *bytes = (uint8_t*)block;
    size_t i, j, k, n[4] = { 0, 1, 2, 3 };

    if (block_size > 6) {
        n[2] = 3;
        n[3] = 4;
    }

    for (i = 0; i < 4; ++i) {
        uint8_t c[4] = { bytes[i], bytes[4+i], bytes[8+i], bytes[12+i] };
        for (j = 0; j < block_size - n[i]; ++j) {
            bytes[j * 4 + i] = bytes[((j + n[i]) % block_size) * 4 + i];
        }
        for (; j < block_size; ++j) {
            bytes[j * 4 + i] = c[(j + n[i]) % 4];
        }
    }
}

static void rijndael_mixcolumns(void *block, size_t block_size) {
    uint8_t *bytes = (uint8_t*)block;
    size_t i;

    for (i = 0; i < block_size; ++i) {
        uint8_t a[4] = { bytes[4*i+0], bytes[4*i+1], bytes[4*i+2], bytes[4*i+3] };
        bytes[4*i+0] = galois(a[0], 2) ^ galois(a[1], 3) ^ a[2] ^ a[3];
        bytes[4*i+1] = galois(a[1], 2) ^ galois(a[2], 3) ^ a[3] ^ a[0];
        bytes[4*i+2] = galois(a[2], 2) ^ galois(a[3], 3) ^ a[0] ^ a[1];
        bytes[4*i+3] = galois(a[3], 2) ^ galois(a[0], 3) ^ a[1] ^ a[2];
    }
}

int rijndael_begin(rijndael_state *state, const uint8_t *key, size_t key_size, size_t block_size, size_t num_rounds) {
    if (key_size < 128 || key_size > 256) return 0;
    if (block_size < 128 || block_size > 256) return 0;

    /* convert number of bits to number of (32-bit) words, rounding up */
    key_size = (key_size + 31) >> 5;
    block_size = (block_size + 31) >> 5;

    if (num_rounds == 0) {
        num_rounds  = (key_size > block_size) ? key_size : block_size;
        num_rounds += 6;
    }

    size_t key_cols = (num_rounds + 1) * block_size;

    /* allocate space for expanded key */
    state->key = malloc(key_cols * sizeof *state->key);

    if (!state->key) return 0;

    size_t i, j, k;

/*
    TRACE("key_size == %u", key_size);
    TRACE("block_size == %u", block_size);
    TRACE("num_rounds == %u", num_rounds);
*/

    state->key_size = key_size;
    state->block_size = block_size;
    state->num_rounds = num_rounds;

    for (k = 0; k < key_size; ++k) {
        state->key[k] = key[k*4+0] | (key[k*4+1]<<8) | (key[k*4+2]<<16) | (key[k*4+3]<<24);
    }

/*
    TRACE("k (after first round) == %u", k);
*/

    for (i = 1; i <= num_rounds && k < key_cols; ++i) {
        uint32_t n = state->key[k - 1];
        n = ror32(n, 8);
        rijndael_subbytes(&n, 1, fsbox);
        n ^= state->key[k - block_size];
        n ^= rcon[i];
        state->key[k++] = n;

        for (j = 1; j < block_size && k < key_cols; ++j) {
            n = state->key[k - 1];
            n ^= state->key[k - block_size];
            state->key[k++] = n;
        }
    }

/*
    TRACE("k (after last round) == %u", k);
*/

    return 1;
}

size_t rijndael_encrypt(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size) {
    uint8_t *indata, *outdata;
    size_t i, j, k, r;

    size_t n;

    indata = (uint8_t*)plaintext;
    outdata = (uint8_t*)ciphertext;

    uint32_t *block = alloca(state->block_size * sizeof *block);

    /* The AddRoundKey step is kept inline below because it depends on local
     * state in the variable 'k'.
     */

    for (i = 0; i < size; i += 4 * state->block_size) {
        PRINT("Round 0");

        for (j = k = 0; j < state->block_size; ++j) {
            block[j]  = indata[i + j * 4 + 0] <<  0;
            block[j] |= indata[i + j * 4 + 1] <<  8;
            block[j] |= indata[i + j * 4 + 2] << 16;
            block[j] |= indata[i + j * 4 + 3] << 24;
        }

        PRINT_BLOCK(block, "    Input Block:");

        for (j = k = 0; j < state->block_size; ++j) {
            block[j] ^= state->key[k++];
        }

        PRINT_BLOCK(block, "    AddRoundKey:");

        for (r = 1; r < state->num_rounds; ++r) {
            PRINT("Round %d", r);

            rijndael_subbytes(block, state->block_size, fsbox);

            PRINT_BLOCK(block, "    SubBytes:   ");

            rijndael_shiftrows(block, state->block_size);

            PRINT_BLOCK(block, "    ShiftRows:  ");

            rijndael_mixcolumns(block, state->block_size);

            PRINT_BLOCK(block, "    MixColumns: ");

            for (j = 0; j < state->block_size; ++j) {
                block[j] ^= state->key[k++];
            }

            PRINT_BLOCK(block, "    AddRoundKey:");
        }

        PRINT("Final Round");

        rijndael_subbytes(block, state->block_size, fsbox);

        PRINT_BLOCK(block, "    SubBytes:   ");

        rijndael_shiftrows(block, state->block_size);

        PRINT_BLOCK(block, "    ShiftRows:  ");

        for (j = 0; j < state->block_size; ++j) {
            block[j] ^= state->key[k++];
            outdata[i + j * 4 + 0] = block[j] >>  0;
            outdata[i + j * 4 + 1] = block[j] >>  8;
            outdata[i + j * 4 + 2] = block[j] >> 16;
            outdata[i + j * 4 + 3] = block[j] >> 24;
        }

        PRINT_BLOCK(block, "    AddRoundKey:");
    }

    return i;
}

size_t rijndael_decrypt(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size) {
    /* TODO */
    return 0;
}

void rijndael_finish(rijndael_state *state) {
    if (state->key) {
        free(state->key);
        state->key = NULL;
    }
}


/* wrappers for above specifically for AES usage */

int aes_begin(aes_state *state, const uint8_t *key, size_t key_size) {
    key_size = (key_size + 63) & (~63);
    return rijndael_begin(state, key, key_size, 128, 0);
}

size_t aes_encrypt(aes_state *state, const void *plaintext, void *ciphertext, size_t size) {
    return rijndael_encrypt(state, plaintext, ciphertext, size);
}

size_t aes_decrypt(aes_state *state, const void *ciphertext, void *plaintext, size_t size) {
    return rijndael_decrypt(state, ciphertext, plaintext, size);
}

void aes_finish(aes_state *state) {
    rijndael_finish(state);
}

