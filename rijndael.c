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

# define PRINT_BLOCK(blk, x, ...) do { \
    fprintf(stderr, ##__VA_ARGS__); \
    for (size_t n = 0; n < x; ++n) { \
        fprintf(stderr, " %02x", ((uint8_t*)blk)[n]); \
    } \
    fputc('\n', stderr); \
} while(0)

#else
# define TRACE(...)
# define PRINT(...)
# define PRINT_BLOCK(...)
#endif

static uint8_t fsbox[256]; /* forward S-box */
static uint8_t rsbox[256]; /* reverse S-box */
static uint8_t rcon[256];
static uint8_t g2[256], g3[256], g9[256], g11[256], g13[256], g14[256];

static uint8_t galois(uint8_t a, uint8_t b) {
    uint8_t n = 0;
    for (uint8_t i = 0; i < 8; ++i) {
        n ^= (a & 1) * b;
        b = (b << 1) ^ ((b >> 7) * 0x1b);
        a >>= 1;
    }
    return n;
}

void rijndael_init_tables(void) {
    static int initialized = 0;

    if (!initialized) {
        uint8_t inv[256];
        inv[0] = 0;
        for (size_t i = 1; i < 256; ++i) {
            for (size_t j = 0; j < 256; ++j) {
                if (galois(i, j) == 1) {
                    inv[i] = j;
                    break;
                }
            }
        }

        TRACE("Initialize `sbox' tables");
        for (size_t i = 0; i < 256; ++i) {
            uint8_t s = inv[i], x = s;
            x ^= (s = (s << 1) | (s >> 7));
            x ^= (s = (s << 1) | (s >> 7));
            x ^= (s = (s << 1) | (s >> 7));
            x ^= (s = (s << 1) | (s >> 7));
            x ^= 0x63;
            fsbox[i] = x;
            rsbox[x] = i;
        }

        TRACE("Initialize `rcon' table");
        uint8_t r = 1;
        for (size_t i = 0; i < 256; ++i) {
            rcon[i] = r;
            r = (r << 1) ^ ((r >> 7) * 0x1b);
        }

        TRACE("Initialize `galois' tables");
        for (size_t i = 0; i < 256; ++i) {
            g2 [i] = galois(i,  2);
            g3 [i] = galois(i,  3);
            g9 [i] = galois(i,  9);
            g11[i] = galois(i, 11);
            g13[i] = galois(i, 13);
            g14[i] = galois(i, 14);
        }

        initialized = 1;
    }
}

void rijndael_addroundkey(void *block, size_t block_size, const void *key) {
    uint32_t *b = block;
    const uint32_t *k = key;
    for (size_t i = 0; i < block_size; ++i) {
        b[i] ^= k[i];
    }
}

void rijndael_subbytes(void *block, size_t block_size) {
    uint8_t *bytes = (uint8_t*)block;
    size_t count = block_size * 4, i;
    for (i = 0; i < count; ++i) {
        bytes[i] = fsbox[bytes[i]];
    }
}

void rijndael_rsubbytes(void *block, size_t block_size) {
    uint8_t *bytes = (uint8_t*)block;
    size_t count = block_size * 4, i;
    for (i = 0; i < count; ++i) {
        bytes[i] = rsbox[bytes[i]];
    }
}

void rijndael_shiftrows(void *block, size_t block_size) {
    uint8_t *bytes = (uint8_t*)block;
    size_t i, j, k, n[4] = { 0, 1, 2, 3 };

    if (block_size > 7) {
        n[2] = 3;
    }
    if (block_size > 6) {
        n[3] = 4;
    }

    for (i = 1; i < 4; ++i) {
        k = block_size - n[i];
        uint8_t c[4];
        for (j = 0; j < n[i]; ++j) c[j] = bytes[j * 4 + i];
        for (; j < block_size; ++j) bytes[(j - n[i]) * 4 + i] = bytes[j * 4 + i];
        for (j = k; j < block_size; ++j) bytes[j * 4 + i] = c[j - k];

    }
}

void rijndael_rshiftrows(void *block, size_t block_size) {
    uint8_t *bytes = (uint8_t*)block;
    size_t i, j, k, n[4] = { 0, 1, 2, 3 };

    if (block_size > 7) {
        n[2] = 3;
    }
    if (block_size > 6) {
        n[3] = 4;
    }

    for (i = 1; i < 4; ++i) {
        k = block_size - n[i];
        uint8_t c[4];
        for (j = k; j < block_size; ++j) c[j - k] = bytes[j * 4 + i];
        for (j = 0; j < k; ++j) bytes[(block_size - j - 1) * 4 + i] = bytes[(block_size - j - 1 - n[i]) * 4 + i];
        for (j = 0; j < n[i]; ++j) bytes[j * 4 + i] = c[j];
    }
}

void rijndael_mixcolumns(void *block, size_t block_size) {
    uint8_t *bytes = (uint8_t*)block;
    size_t i;

    for (i = 0; i < block_size; ++i) {
        uint8_t a[4] = { bytes[4*i+0], bytes[4*i+1], bytes[4*i+2], bytes[4*i+3] };
        bytes[4*i+0] = g2[a[0]] ^ g3[a[1]] ^ a[2] ^ a[3];
        bytes[4*i+1] = g2[a[1]] ^ g3[a[2]] ^ a[3] ^ a[0];
        bytes[4*i+2] = g2[a[2]] ^ g3[a[3]] ^ a[0] ^ a[1];
        bytes[4*i+3] = g2[a[3]] ^ g3[a[0]] ^ a[1] ^ a[2];
    }
}

void rijndael_rmixcolumns(void *block, size_t block_size) {
    uint8_t *bytes = (uint8_t*)block;
    size_t i;

    for (i = 0; i < block_size; ++i) {
        uint8_t a[4] = { bytes[4*i+0], bytes[4*i+1], bytes[4*i+2], bytes[4*i+3] };
        bytes[4*i+0] = g14[a[0]] ^ g11[a[1]] ^ g13[a[2]] ^ g9[a[3]];
        bytes[4*i+1] = g14[a[1]] ^ g11[a[2]] ^ g13[a[3]] ^ g9[a[0]];
        bytes[4*i+2] = g14[a[2]] ^ g11[a[3]] ^ g13[a[0]] ^ g9[a[1]];
        bytes[4*i+3] = g14[a[3]] ^ g11[a[0]] ^ g13[a[1]] ^ g9[a[2]];
    }
}

int rijndael_begin(rijndael_state *state, const uint8_t *key, size_t key_size, size_t block_size, size_t num_rounds) {
    rijndael_init_tables();

    if (key_size < 128 || key_size > 256) return 0;
    if (block_size < 128 || block_size > 256) return 0;

    /* convert number of bits to number of (32-bit) words, rounding down */
    key_size = key_size >> 5;
    block_size = block_size >> 5;

    if (num_rounds == 0) {
        num_rounds  = (key_size > block_size) ? key_size : block_size;
        num_rounds += 6;
    }

    size_t key_cols = (num_rounds + 1) * block_size;

    if (!state->key) return 0;

    size_t i, j, k;

    state->key_size = key_size;
    state->block_size = block_size;
    state->num_rounds = num_rounds;

    PRINT_BLOCK(key, key_size*4, "Input Key:      ");

    for (k = 0; k < key_size; ++k) {
        state->key[k] = key[k*4+0] | (key[k*4+1]<<8) | (key[k*4+2]<<16) | (key[k*4+3]<<24);
    }

    TRACE("k (after first round) == %u", k);

    for (i = 0; k < key_cols; ++k) {
        uint32_t n = state->key[k - 1];
        if ((k % key_size) == 0) {
            n = (n >> 8) | (n << 24);
            rijndael_subbytes(&n, 1);
            n ^= rcon[i++];
        } else if ((key_size > 6) && ((k % key_size) == 4)) {
            rijndael_subbytes(&n, 1);
        }
        n ^= state->key[k - key_size];
        state->key[k] = n;
    }

    TRACE("k (after last round) == %u", k);

    return 1;
}

size_t rijndael_encrypt(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size) {
    uint8_t *indata, *outdata;
    size_t i, j, r;

    size_t n;

    indata = (uint8_t*)plaintext;
    outdata = (uint8_t*)ciphertext;

    uint32_t *block = state->block;

    for (i = 0; i < size; i += 4 * state->block_size) {
        PRINT("Round 0");

        uint32_t *key = state->key;

        TRACE("k == %d", key - state->key);

        for (j = 0; j < state->block_size; ++j) {
            block[j]  = indata[i + j * 4 + 0] <<  0;
            block[j] |= indata[i + j * 4 + 1] <<  8;
            block[j] |= indata[i + j * 4 + 2] << 16;
            block[j] |= indata[i + j * 4 + 3] << 24;
        }

        PRINT_BLOCK(block, state->block_size*4, "    Input Block:");

        rijndael_addroundkey(block, state->block_size, key);
        key += state->block_size;
        PRINT_BLOCK(block, state->block_size*4, "    AddRoundKey:");

        for (r = 1; r < state->num_rounds; ++r) {
            PRINT("Round %d", r);

            rijndael_subbytes(block, state->block_size);
            PRINT_BLOCK(block, state->block_size*4, "    SubBytes:   ");

            rijndael_shiftrows(block, state->block_size);
            PRINT_BLOCK(block, state->block_size*4, "    ShiftRows:  ");

            rijndael_mixcolumns(block, state->block_size);
            PRINT_BLOCK(block, state->block_size*4, "    MixColumns: ");

            rijndael_addroundkey(block, state->block_size, key);
            key += state->block_size;
            PRINT_BLOCK(block, state->block_size*4, "    AddRoundKey:");
        }

        PRINT("Final Round");

        TRACE("k == %d", key - state->key);

        rijndael_subbytes(block, state->block_size);
        PRINT_BLOCK(block, state->block_size*4, "    SubBytes:   ");

        rijndael_shiftrows(block, state->block_size);
        PRINT_BLOCK(block, state->block_size*4, "    ShiftRows:  ");

        rijndael_addroundkey(block, state->block_size, key);
        PRINT_BLOCK(block, state->block_size*4, "    AddRoundKey:");

        for (j = 0; j < state->block_size; ++j) {
            outdata[i + j * 4 + 0] = block[j] >>  0;
            outdata[i + j * 4 + 1] = block[j] >>  8;
            outdata[i + j * 4 + 2] = block[j] >> 16;
            outdata[i + j * 4 + 3] = block[j] >> 24;
        }
    }

    return i;
}

size_t rijndael_decrypt(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size) {
    uint8_t *indata, *outdata;
    size_t i, j, r;

    size_t n;

    indata = (uint8_t*)ciphertext;
    outdata = (uint8_t*)plaintext;

    uint32_t *block = state->block;

    for (i = 0; i < size; i += 4 * state->block_size) {
        PRINT("Round 0");

        uint32_t *key = state->key + state->block_size * state->num_rounds;

        TRACE("k == %d", key - state->key);

        for (j = 0; j < state->block_size; ++j) {
            block[j]  = indata[i + j * 4 + 0] <<  0;
            block[j] |= indata[i + j * 4 + 1] <<  8;
            block[j] |= indata[i + j * 4 + 2] << 16;
            block[j] |= indata[i + j * 4 + 3] << 24;
        }

        PRINT_BLOCK(block, state->block_size*4, "    Input Block:");

        rijndael_addroundkey(block, state->block_size, key);
        key -= state->block_size;
        PRINT_BLOCK(block, state->block_size*4, "    AddRoundKey:");

        rijndael_rshiftrows(block, state->block_size);
        PRINT_BLOCK(block, state->block_size*4, "    RShiftRows: ");

        rijndael_rsubbytes(block, state->block_size);
        PRINT_BLOCK(block, state->block_size*4, "    RSubBytes:  ");

        for (r = 1; r < state->num_rounds; ++r) {
            PRINT("Round %d", r);

            rijndael_addroundkey(block, state->block_size, key);
            key -= state->block_size;
            PRINT_BLOCK(block, state->block_size*4, "    AddRoundKey:");

            rijndael_rmixcolumns(block, state->block_size);
            PRINT_BLOCK(block, state->block_size*4, "    RMixColumns:");

            rijndael_rshiftrows(block, state->block_size);
            PRINT_BLOCK(block, state->block_size*4, "    RShiftRows: ");

            rijndael_rsubbytes(block, state->block_size);
            PRINT_BLOCK(block, state->block_size*4, "    RSubBytes:  ");
        }

        PRINT("Final Round");

        TRACE("k == %d", key - state->key);

        rijndael_addroundkey(block, state->block_size, key);
        PRINT_BLOCK(block, state->block_size*4, "    AddRoundKey:");

        for (j = 0; j < state->block_size; ++j) {
            outdata[i + j * 4 + 0] = block[j] >>  0;
            outdata[i + j * 4 + 1] = block[j] >>  8;
            outdata[i + j * 4 + 2] = block[j] >> 16;
            outdata[i + j * 4 + 3] = block[j] >> 24;
        }
    }

    return i;
}

void rijndael_finish(rijndael_state *state) {
    state->key_size = 0;
    state->block_size = 0;
    state->num_rounds = 0;
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

