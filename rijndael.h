#ifndef RIJNDAEL_H_INCLUDED
#define RIJNDAEL_H_INCLUDED 1

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rijndael_state {
    uint32_t key[120];
    uint32_t block[8];
    uint8_t key_size;
    uint8_t block_size;
    uint8_t num_rounds;
} rijndael_state, aes_state;

/* general Rijndael algorithm */
int rijndael_begin(rijndael_state *state, const uint8_t *key, size_t key_size, size_t block_size, size_t num_rounds);
size_t rijndael_encrypt(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size);
size_t rijndael_decrypt(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size);
void rijndael_finish(rijndael_state *state);

/* wrappers for above specifically for AES usage */
int aes_begin(aes_state *state, const uint8_t *key, size_t key_size);
size_t aes_encrypt(aes_state *state, const void *plaintext, void *ciphertext, size_t size);
size_t aes_decrypt(aes_state *state, const void *ciphertext, void *plaintext, size_t size);
void aes_finish(aes_state *state);

#ifdef __cplusplus
}
#endif

#endif /*RIJNDAEL_H_INCLUDED*/
