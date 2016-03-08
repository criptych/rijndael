#ifndef RIJNDAEL_H_INCLUDED
#define RIJNDAEL_H_INCLUDED 1

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rijndael_state {
    uint32_t key[120];
    uint32_t iv[8];
    uint8_t key_size;
    uint8_t block_size;
    uint8_t num_rounds;
} rijndael_state, aes_state;

/* general Rijndael algorithm */
int rijndael_init(rijndael_state *state, const void *key, size_t key_size, size_t block_size, size_t num_rounds);
int rijndael_init_iv(rijndael_state *state, const void *key, size_t key_size, size_t block_size, size_t num_rounds, const void *iv);
void rijndael_set_iv(rijndael_state *state, const void *iv);
size_t rijndael_encrypt_ecb(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size);
size_t rijndael_encrypt_cbc(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size);
size_t rijndael_encrypt_ofb(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size);
size_t rijndael_encrypt_cfb(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size);
size_t rijndael_decrypt_ecb(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size);
size_t rijndael_decrypt_cbc(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size);
size_t rijndael_decrypt_ofb(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size);
size_t rijndael_decrypt_cfb(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size);

/* wrappers for above specifically for AES usage */
int aes_init(aes_state *state, const void *key, size_t key_size);
int aes_init_iv(aes_state *state, const void *key, size_t key_size, const void *iv);
void aes_set_iv(aes_state *state, const void *iv);
size_t aes_encrypt_ecb(aes_state *state, const void *plaintext, void *ciphertext, size_t size);
size_t aes_encrypt_cbc(aes_state *state, const void *plaintext, void *ciphertext, size_t size);
size_t aes_encrypt_ofb(aes_state *state, const void *plaintext, void *ciphertext, size_t size);
size_t aes_encrypt_cfb(aes_state *state, const void *plaintext, void *ciphertext, size_t size);
size_t aes_decrypt_ecb(aes_state *state, const void *ciphertext, void *plaintext, size_t size);
size_t aes_decrypt_cbc(aes_state *state, const void *ciphertext, void *plaintext, size_t size);
size_t aes_decrypt_ofb(aes_state *state, const void *ciphertext, void *plaintext, size_t size);
size_t aes_decrypt_cfb(aes_state *state, const void *ciphertext, void *plaintext, size_t size);

#ifdef __cplusplus
}
#endif

#endif /*RIJNDAEL_H_INCLUDED*/
