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

#define SHOW_ROUNDS

static uint8_t fsbox[256]; /* forward S-box */
static uint8_t rsbox[256]; /* reverse S-box */
static uint8_t rcon[256];

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

        initialized = 1;
    }
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

    if (block_size > 7) {
        n[2] = 3;
    }
    if (block_size > 6) {
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

static void rijndael_rshiftrows(void *block, size_t block_size) {
    uint8_t *bytes = (uint8_t*)block;
    size_t i, j, k, n[4] = { 0, 1, 2, 3 };

    if (block_size > 7) {
        n[2] = 3;
    }
    if (block_size > 6) {
        n[3] = 4;
    }

    for (i = 0; i < 4; ++i) {
        uint8_t c[4] = { bytes[i], bytes[4+i], bytes[8+i], bytes[12+i] };
        for (j = 0; j < block_size - n[i]; ++j) {
            bytes[j * 4 + i] = bytes[((j + block_size - n[i]) % block_size) * 4 + i];
        }
        for (; j < block_size; ++j) {
            bytes[j * 4 + i] = c[(j + block_size - n[i]) % 4];
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

static void rijndael_rmixcolumns(void *block, size_t block_size) {
    uint8_t *bytes = (uint8_t*)block;
    size_t i;

    for (i = 0; i < block_size; ++i) {
        uint8_t a[4] = { bytes[4*i+0], bytes[4*i+1], bytes[4*i+2], bytes[4*i+3] };
        bytes[4*i+0] = galois(a[0], 14) ^ galois(a[1], 11) ^ galois(a[2], 13) ^ galois(a[3], 9);
        bytes[4*i+1] = galois(a[1], 14) ^ galois(a[2], 11) ^ galois(a[3], 13) ^ galois(a[0], 9);
        bytes[4*i+2] = galois(a[2], 14) ^ galois(a[3], 11) ^ galois(a[0], 13) ^ galois(a[1], 9);
        bytes[4*i+3] = galois(a[3], 14) ^ galois(a[0], 11) ^ galois(a[1], 13) ^ galois(a[2], 9);
    }
}

int rijndael_begin(rijndael_state *state, const uint8_t *key, size_t key_size, size_t block_size, size_t num_rounds) {
    rijndael_init_tables();

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
    state->key = malloc(2 * key_cols * sizeof *state->key);

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

    PRINT_BLOCK(key, key_size*4, "Input Key:      ");

    for (k = 0; k < key_size; ++k) {
        state->key[k] = key[k*4+0] | (key[k*4+1]<<8) | (key[k*4+2]<<16) | (key[k*4+3]<<24);
    }

    TRACE("k (after first round) == %u", k);

    for (i = 0; k < key_cols; ++k) {
        uint32_t n = state->key[k - 1];
        if ((k % key_size) == 0) {
            n = ror32(n, 8);
            rijndael_subbytes(&n, 1, fsbox);
            n ^= rcon[i++];
        } else if ((key_size > 6) && ((k % key_size) == 4)) {
            rijndael_subbytes(&n, 1, fsbox);
        }
        n ^= state->key[k - key_size];
        state->key[k] = n;
    }

    for (i = 0; i <= num_rounds; ++i) {
        for (j = 0; j < block_size; ++j) {
            state->key[key_cols+i*block_size+j] = state->key[(num_rounds - i)*block_size+j];
        }
    }

    rijndael_rmixcolumns(&(state->key[key_cols+block_size]), key_cols-2*block_size);

    TRACE("k (after last round) == %u", k);

    return 1;
}

size_t rijndael_encrypt(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size) {
    uint8_t *indata, *outdata;
    size_t i, j, k, r;

    size_t n;

    indata = (uint8_t*)plaintext;
    outdata = (uint8_t*)ciphertext;

    uint32_t block[8]; /* max size */

    /* The AddRoundKey step is kept inline below because it depends on local
     * state in the variable 'k'.
     */

    for (i = 0; i < size; i += 4 * state->block_size) {
        PRINT("Round 0");

        for (j = 0; j < state->block_size; ++j) {
            block[j]  = indata[i + j * 4 + 0] <<  0;
            block[j] |= indata[i + j * 4 + 1] <<  8;
            block[j] |= indata[i + j * 4 + 2] << 16;
            block[j] |= indata[i + j * 4 + 3] << 24;
        }

        PRINT_BLOCK(block, state->block_size*4, "    Input Block:");

        for (j = k = 0; j < state->block_size; ++j) {
            block[j] ^= state->key[k++];
        }

        PRINT_BLOCK(block, state->block_size*4, "    AddRoundKey:");

        for (r = 1; r < state->num_rounds; ++r) {
            PRINT("Round %d", r);

            rijndael_subbytes(block, state->block_size, fsbox);
            PRINT_BLOCK(block, state->block_size*4, "    SubBytes:   ");

            rijndael_shiftrows(block, state->block_size);
            PRINT_BLOCK(block, state->block_size*4, "    ShiftRows:  ");

            rijndael_mixcolumns(block, state->block_size);
            PRINT_BLOCK(block, state->block_size*4, "    MixColumns: ");

            for (j = 0; j < state->block_size; ++j) {
                block[j] ^= state->key[k++];
            }
            PRINT_BLOCK(block, state->block_size*4, "    AddRoundKey:");
        }

        PRINT("Final Round");

        rijndael_subbytes(block, state->block_size, fsbox);
        PRINT_BLOCK(block, state->block_size*4, "    SubBytes:   ");

        rijndael_shiftrows(block, state->block_size);
        PRINT_BLOCK(block, state->block_size*4, "    ShiftRows:  ");

        for (j = 0; j < state->block_size; ++j) {
            block[j] ^= state->key[k++];
        }
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
    size_t i, j, k, r;

    size_t n;

    indata = (uint8_t*)ciphertext;
    outdata = (uint8_t*)plaintext;

    uint32_t block[8]; /* max size */

    /* The AddRoundKey step is kept inline below because it depends on local
     * state in the variable 'k'.
     */

    for (i = 0; i < size; i += 4 * state->block_size) {
        PRINT("Round 0");

        for (j = 0; j < state->block_size; ++j) {
            block[j]  = indata[i + j * 4 + 0] <<  0;
            block[j] |= indata[i + j * 4 + 1] <<  8;
            block[j] |= indata[i + j * 4 + 2] << 16;
            block[j] |= indata[i + j * 4 + 3] << 24;
        }

        PRINT_BLOCK(block, state->block_size*4, "    Input Block:");

        for (j = 0, k = state->num_rounds * state->block_size; j < state->block_size; ++j) {
            block[j] ^= state->key[k + j];
        }
        k -= state->block_size;
        PRINT_BLOCK(block, state->block_size*4, "    AddRoundKey:");

        rijndael_rshiftrows(block, state->block_size);
        PRINT_BLOCK(block, state->block_size*4, "    ShiftRows:  ");

        rijndael_subbytes(block, state->block_size, rsbox);
        PRINT_BLOCK(block, state->block_size*4, "    SubBytes:   ");

        for (r = 1; r < state->num_rounds; ++r) {
            PRINT("Round %d", r);

            for (j = 0; j < state->block_size; ++j) {
                block[j] ^= state->key[k + j];
            }
            k -= state->block_size;
            PRINT_BLOCK(block, state->block_size*4, "    AddRoundKey:");

            rijndael_rmixcolumns(block, state->block_size);
            PRINT_BLOCK(block, state->block_size*4, "    MixColumns: ");

            rijndael_rshiftrows(block, state->block_size);
            PRINT_BLOCK(block, state->block_size*4, "    ShiftRows:  ");

            rijndael_subbytes(block, state->block_size, rsbox);
            PRINT_BLOCK(block, state->block_size*4, "    SubBytes:   ");
        }

        PRINT("Final Round");

        TRACE("k == %u", k);

        for (j = 0; j < state->block_size; ++j) {
            block[j] ^= state->key[k + j];
        }
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

