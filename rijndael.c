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

static inline uint32_t getword(const void *p) {
    return (((const uint8_t*)p)[0] <<  0) |
           (((const uint8_t*)p)[1] <<  8) |
           (((const uint8_t*)p)[2] << 16) |
           (((const uint8_t*)p)[3] << 24);
}

static inline void putword(void *p, uint32_t w) {
    ((uint8_t*)p)[0] = w >>  0;
    ((uint8_t*)p)[1] = w >>  8;
    ((uint8_t*)p)[2] = w >> 16;
    ((uint8_t*)p)[3] = w >> 24;
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

        uint8_t r = 1;
        for (size_t i = 0; i < 256; ++i) {
            rcon[i] = r;
            r = (r << 1) ^ ((r >> 7) * 0x1b);
        }

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
    uint8_t c[4];

    if (block_size > 7) n[2] = 3;
    if (block_size > 6) n[3] = 4;

    for (i = 1; i < 4; ++i) {
        k = block_size - n[i];
        for (j = 0; j < n[i]; ++j) {
            c[j] = bytes[j * 4 + i];
        }
        for (; j < block_size; ++j) {
            bytes[(j - n[i]) * 4 + i] = bytes[j * 4 + i];
        }
        for (j = k; j < block_size; ++j) {
            bytes[j * 4 + i] = c[j - k];
        }
    }
}

void rijndael_rshiftrows(void *block, size_t block_size) {
    uint8_t *bytes = (uint8_t*)block;
    size_t i, j, k, n[4] = { 0, 1, 2, 3 };
    uint8_t c[4];

    if (block_size > 7) n[2] = 3;
    if (block_size > 6) n[3] = 4;

    for (i = 1; i < 4; ++i) {
        k = block_size - n[i];
        for (j = k; j < block_size; ++j) {
            c[j - k] = bytes[j * 4 + i];
        }
        for (j = 0; j < k; ++j) {
            bytes[(block_size - j - 1) * 4 + i] = bytes[(block_size - j - 1 - n[i]) * 4 + i];
        }
        for (j = 0; j < n[i]; ++j) {
            bytes[j * 4 + i] = c[j];
        }
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

int rijndael_init(rijndael_state *state, const void *key, size_t key_size, size_t block_size, size_t num_rounds) {
    rijndael_init_tables();

    if (key_size < 128 || key_size > 256) return 0;
    if (block_size < 128 || block_size > 256) return 0;

    /* convert number of bits to number of (32-bit) words, rounding down */
    key_size = key_size >> 5;
    block_size = block_size >> 5;

    if (num_rounds == 0) {
        num_rounds = ((key_size > block_size) ? key_size : block_size) + 6;
    }

    size_t key_cols = (num_rounds + 1) * block_size;

    state->key_size = key_size;
    state->block_size = block_size;
    state->num_rounds = num_rounds;

    const uint32_t *k = key;

    size_t i;

    for (i = 0; i < key_size; ++i) {
        state->key[i] = getword(k++);
    }

    for (size_t j = 0; i < key_cols; ++i) {
        uint32_t n = state->key[i - 1];
        if ((i % key_size) == 0) {
            n = (n >> 8) | (n << 24);
            rijndael_subbytes(&n, 1);
            n ^= rcon[j++];
        } else if ((key_size > 6) && ((i % key_size) == 4)) {
            rijndael_subbytes(&n, 1);
        }
        n ^= state->key[i - key_size];
        state->key[i] = n;
    }

    return 1;
}

int rijndael_init_iv(rijndael_state *state, const void *key, size_t key_size, size_t block_size, size_t num_rounds, const void *iv) {
    int rv = rijndael_init(state, key, key_size, block_size, num_rounds);
    if (rv) rijndael_set_iv(state, iv);
    return rv;
}

void rijndael_set_iv(rijndael_state *state, const void *iv) {
    if (iv) {
        for (size_t k = 0; k < state->block_size; ++k) {
            state->iv[k] = getword((uint8_t*)iv+k*4);
        }
    } else {
        for (size_t k = 0; k < state->block_size; ++k) {
            state->iv[k] = 0;
        }
    }
}

void rijndael_encrypt_block(rijndael_state *state, void *block) {
    uint32_t *key = state->key;

    rijndael_addroundkey(block, state->block_size, key);
    key += state->block_size;

    for (size_t r = 1; r < state->num_rounds; ++r) {
        rijndael_subbytes(block, state->block_size);
        rijndael_shiftrows(block, state->block_size);
        rijndael_mixcolumns(block, state->block_size);
        rijndael_addroundkey(block, state->block_size, key);
        key += state->block_size;
    }

    rijndael_subbytes(block, state->block_size);
    rijndael_shiftrows(block, state->block_size);
    rijndael_addroundkey(block, state->block_size, key);
}

void rijndael_decrypt_block(rijndael_state *state, void *block) {
    uint32_t *key = state->key + state->block_size * state->num_rounds;

    rijndael_addroundkey(block, state->block_size, key);
    key -= state->block_size;
    rijndael_rshiftrows(block, state->block_size);
    rijndael_rsubbytes(block, state->block_size);

    for (size_t r = 1; r < state->num_rounds; ++r) {
        rijndael_addroundkey(block, state->block_size, key);
        key -= state->block_size;
        rijndael_rmixcolumns(block, state->block_size);
        rijndael_rshiftrows(block, state->block_size);
        rijndael_rsubbytes(block, state->block_size);
    }

    rijndael_addroundkey(block, state->block_size, key);
}

size_t rijndael_encrypt_ecb(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size) {
    const uint32_t *indata = plaintext;
    uint32_t *outdata = ciphertext;
    uint32_t block[8];

    size_t i;

    for (i = 0; i < size; i += 4 * state->block_size) {

        for (size_t j = 0; j < state->block_size; ++j) {
            block[j] = getword(indata++);
        }

        rijndael_encrypt_block(state, block);

        for (size_t j = 0; j < state->block_size; ++j) {
            putword(outdata++, block[j]);
        }
    }

    return i;
}

size_t rijndael_encrypt_cbc(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size) {
    const uint32_t *indata = plaintext;
    uint32_t *outdata = ciphertext;

    uint32_t block[8];

    size_t i;

    for (i = 0; i < size; i += 4 * state->block_size) {

        for (size_t j = 0; j < state->block_size; ++j) {
            block[j] = getword(indata++) ^ state->iv[j];
        }

        rijndael_encrypt_block(state, block);

        for (size_t j = 0; j < state->block_size; ++j) {
            putword(outdata++, state->iv[j] = block[j]);
        }
    }

    return i;
}

size_t rijndael_encrypt_ofb(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size) {
    const uint32_t *indata = plaintext;
    uint32_t *outdata = ciphertext;

    size_t i;

    for (i = 0; i < size; i += 4 * state->block_size) {
        rijndael_encrypt_block(state, state->iv);

        for (size_t j = 0; j < state->block_size; ++j) {
            putword(outdata++, getword(indata++) ^ state->iv[j]);
        }
    }

    return i;
}

size_t rijndael_encrypt_cfb8(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size) {
    uint8_t *indata, *outdata;
    size_t i, j;

    indata = (uint8_t*)plaintext;
    outdata = (uint8_t*)ciphertext;

    for (i = 0; i < size; i += 1) {

        rijndael_encrypt_block(state, state->iv);

        outdata[i] = indata[i] ^ state->iv[0];

        for (j = state->block_size-1; j > 0; --j) {
            state->iv[j] = (state->iv[j] >> 8) | (state->iv[j-1] << 24);
        }

        state->iv[j] = (state->iv[j] >> 8) | (outdata[i] << 24);
    }

    return i;
}

size_t rijndael_encrypt_cfb(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size) {
    const uint32_t *indata = plaintext;
    uint32_t *outdata = ciphertext;

    size_t i;

    for (i = 0; i < size; i += 4 * state->block_size) {

        rijndael_encrypt_block(state, state->iv);

        for (size_t j = 0; j < state->block_size; ++j) {
            putword(outdata++, state->iv[j] = getword(indata++) ^ state->iv[j]);
        }
    }

    return i;
}

size_t rijndael_decrypt_ecb(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size) {
    const uint32_t *indata = ciphertext;
    uint32_t *outdata = plaintext;

    uint32_t block[8];

    size_t i;

    for (i = 0; i < size; i += 4 * state->block_size) {

        for (size_t j = 0; j < state->block_size; ++j) {
            block[j] = getword(indata++);
        }

        rijndael_decrypt_block(state, block);

        for (size_t j = 0; j < state->block_size; ++j) {
            putword(outdata++, block[j]);
        }
    }

    return i;
}

size_t rijndael_decrypt_cbc(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size) {
    const uint32_t *indata = ciphertext;
    uint32_t *outdata = plaintext;

    uint32_t block[8];
    uint32_t newiv[8];

    size_t i;

    for (i = 0; i < size; i += 4 * state->block_size) {

        for (size_t j = 0; j < state->block_size; ++j) {
            newiv[j] = block[j] = getword(indata++);
        }

        rijndael_decrypt_block(state, block);

        for (size_t j = 0; j < state->block_size; ++j) {
            putword(outdata++, block[j] ^= state->iv[j]);
            state->iv[j] = newiv[j];
        }
    }

    return i;
}

size_t rijndael_decrypt_ofb(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size) {
    return rijndael_encrypt_ofb(state, ciphertext, plaintext, size);
}

size_t rijndael_decrypt_cfb8(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size) {
    uint8_t *indata, *outdata;
    size_t i, j;

    indata = (uint8_t*)ciphertext;
    outdata = (uint8_t*)plaintext;

    for (i = 0; i < size; i += 1) {

        rijndael_encrypt_block(state, state->iv);

        outdata[i] = indata[i] ^ state->iv[0];

        for (j = state->block_size-1; j > 0; --j) {
            state->iv[j] = (state->iv[j] >> 8) | (state->iv[j-1] << 24);
        }

        state->iv[j] = (state->iv[j] >> 8) | (outdata[i] << 24);
    }

    return i;
}

size_t rijndael_decrypt_cfb(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size) {
    const uint32_t *indata = ciphertext;
    uint32_t *outdata = plaintext;

    size_t i;

    for (i = 0; i < size; i += 4 * state->block_size) {

        rijndael_encrypt_block(state, state->iv);

        for (size_t j = 0; j < state->block_size; ++j) {
            uint32_t t = getword(indata++) ^ state->iv[j];
            putword(outdata++, t);
            state->iv[j] ^= t;
        }
    }

    return i;
}

/* wrappers for above specifically for AES usage */

int aes_init(aes_state *state, const void *key, size_t key_size) {
    return rijndael_init(state, key, (key_size + 63) & (~63), 128, 0);
}

int aes_init_iv(aes_state *state, const void *key, size_t key_size, const void *iv) {
    return rijndael_init_iv(state, key, (key_size + 63) & (~63), 128, 0, iv);
}

void aes_set_iv(aes_state *state, const void *iv) {
    rijndael_set_iv(state, iv);
}

size_t aes_encrypt_ecb(aes_state *state, const void *plaintext, void *ciphertext, size_t size) {
    return rijndael_encrypt_ecb(state, plaintext, ciphertext, size);
}

size_t aes_encrypt_cbc(aes_state *state, const void *plaintext, void *ciphertext, size_t size) {
    return rijndael_encrypt_cbc(state, plaintext, ciphertext, size);
}

size_t aes_encrypt_ofb(aes_state *state, const void *plaintext, void *ciphertext, size_t size) {
    return rijndael_encrypt_ofb(state, plaintext, ciphertext, size);
}

size_t aes_encrypt_cfb8(aes_state *state, const void *plaintext, void *ciphertext, size_t size) {
    return rijndael_encrypt_cfb8(state, plaintext, ciphertext, size);
}

size_t aes_encrypt_cfb128(aes_state *state, const void *plaintext, void *ciphertext, size_t size) {
    return rijndael_encrypt_cfb(state, plaintext, ciphertext, size);
}

size_t aes_encrypt_cfb(aes_state *state, const void *plaintext, void *ciphertext, size_t size) {
    return rijndael_encrypt_cfb(state, plaintext, ciphertext, size);
}

size_t aes_decrypt_ecb(aes_state *state, const void *ciphertext, void *plaintext, size_t size) {
    return rijndael_decrypt_ecb(state, ciphertext, plaintext, size);
}

size_t aes_decrypt_cbc(aes_state *state, const void *ciphertext, void *plaintext, size_t size) {
    return rijndael_decrypt_cbc(state, ciphertext, plaintext, size);
}

size_t aes_decrypt_ofb(aes_state *state, const void *ciphertext, void *plaintext, size_t size) {
    return rijndael_decrypt_ofb(state, ciphertext, plaintext, size);
}

size_t aes_decrypt_cfb8(aes_state *state, const void *ciphertext, void *plaintext, size_t size) {
    return rijndael_decrypt_cfb8(state, ciphertext, plaintext, size);
}

size_t aes_decrypt_cfb128(aes_state *state, const void *ciphertext, void *plaintext, size_t size) {
    return rijndael_decrypt_cfb(state, ciphertext, plaintext, size);
}

size_t aes_decrypt_cfb(aes_state *state, const void *ciphertext, void *plaintext, size_t size) {
    return rijndael_decrypt_cfb(state, ciphertext, plaintext, size);
}

