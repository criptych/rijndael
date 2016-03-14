/******************************************************************************\
 *
\******************************************************************************/

#ifndef RIJNDAEL_H_INCLUDED
#define RIJNDAEL_H_INCLUDED 1

/******************************************************************************/

#include <inttypes.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

/**
 * @brief
 * State used during encryption/decryption.
 *
 * Contains the expanded key, current IV, and cipher parameters.  To preserve
 * cipher integrity this should be treated as READ-ONLY outside of the library.
 */
typedef struct rijndael_state {
    /** Expanded key; max size == 8 words * 14(+1) rounds == 120 words. */
    uint32_t key[120];
    /** Current IV; max size == 8 words. May change during encryption/decryption. */
    uint32_t iv[8];
    /** Key size (in words), 4 <= key_size <= 8. (AES: Must be 4, 6, or 8.)*/
    uint8_t key_size;
    /** Block size (in words), 4 <= block_size <= 8. (AES: Must be 4.) */
    uint8_t block_size;
    /** Round count, 10 <= num_rounds <= 14. (AES: Must be 10, 12, or 14.) */
    uint8_t num_rounds;
} rijndael_state;

/**
 * Initialize state with the given key and parameters.
 *
 * This function does not modify the state's current IV.  Use it only with ECB
 * mode, which does not require an IV.  The key is copied into the state, so
 * the original value does not need to remain after this function returns.
 *
 * @returns Zero (0) if parameters are invalid, non-zero otherwise.
 */
int rijndael_init(rijndael_state *state, const void *key, size_t key_size, size_t block_size, size_t num_rounds);

/**
 * Initialize state with the given key, parameters, and IV.
 *
 * Used this function when encrypting or decrypting in CBC, OFB, or CFB modes.
 * The key and IV are copied into the state, so the original values do not need
 * to remain after this function returns.
 *
 * @returns Zero (0) if parameters are invalid, non-zero otherwise.
 */
int rijndael_init_iv(rijndael_state *state, const void *key, size_t key_size, size_t block_size, size_t num_rounds, const void *iv);

/**
 * Load a new IV into the state.
 *
 * Use this function to replace the state's current IV.  The IV is copied into
 * the state, so the original value does not need to remain after this function
 * returns.
 */
void rijndael_set_iv(rijndael_state *state, const void *iv);

/**
 * Encrypt a message in ECB mode.
 *
 * @returns The actual number of bytes encrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t rijndael_encrypt_ecb(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size);

/**
 * Encrypt a message in CBC mode.
 *
 * @returns The actual number of bytes encrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t rijndael_encrypt_cbc(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size);

/**
 * Encrypt a message in OFB mode.
 *
 * @returns The actual number of bytes encrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the word size.
 */
size_t rijndael_encrypt_ofb(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size);

/**
 * Encrypt a message in CFB mode with 8-bit synchronization.
 *
 * @returns The actual number of bytes encrypted.
 */
size_t rijndael_encrypt_cfb8(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size);

/**
 * Encrypt a message in CFB mode with block synchronization.
 *
 * @returns The actual number of bytes encrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the word size.
 */
size_t rijndael_encrypt_cfb(rijndael_state *state, const void *plaintext, void *ciphertext, size_t size);

/**
 * Decrypt a message in ECB mode.
 *
 * @returns The actual number of bytes decrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t rijndael_decrypt_ecb(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size);

/**
 * Decrypt a message in CBC mode.
 *
 * @returns The actual number of bytes decrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t rijndael_decrypt_cbc(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size);

/**
 * Decrypt a message in OFB mode.
 *
 * @returns The actual number of bytes decrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the word size.
 */
size_t rijndael_decrypt_ofb(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size);

/**
 * Decrypt a message in CFB mode with 8-bit synchronization.
 *
 * @returns The actual number of bytes decrypted.
 */
size_t rijndael_decrypt_cfb8(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size);

/**
 * Decrypt a message in CFB mode with block synchronization.
 *
 * @returns The actual number of bytes decrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the word size.
 */
size_t rijndael_decrypt_cfb(rijndael_state *state, const void *ciphertext, void *plaintext, size_t size);

/******************************************************************************/

typedef rijndael_state aes_state;

/**
 * Initialize state with the given key and parameters.
 *
 * This function does not modify the state's current IV.  Use it only with ECB
 * mode, which does not require an IV.  The key is copied into the state, so
 * the original value does not need to remain after this function returns.
 *
 * @returns Zero (0) if parameters are invalid, non-zero otherwise.
 */
int aes_init(aes_state *state, const void *key, size_t key_size);

/**
 * Initialize state with the given key, parameters, and IV.
 *
 * Used this function when encrypting or decrypting in CBC, OFB, or CFB modes.
 * The key and IV are copied into the state, so the original values do not need
 * to remain after this function returns.
 *
 * @returns Zero (0) if parameters are invalid, non-zero otherwise.
 */
int aes_init_iv(aes_state *state, const void *key, size_t key_size, const void *iv);

/**
 * Load a new IV into the state.
 *
 * Use this function to replace the state's current IV.  The IV is copied into
 * the state, so the original value does not need to remain after this function
 * returns.
 */
void aes_set_iv(aes_state *state, const void *iv);

/**
 * Encrypt a message in ECB mode.
 *
 * @returns The actual number of bytes encrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t aes_encrypt_ecb(aes_state *state, const void *plaintext, void *ciphertext, size_t size);

/**
 * Encrypt a message in CBC mode.
 *
 * @returns The actual number of bytes encrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t aes_encrypt_cbc(aes_state *state, const void *plaintext, void *ciphertext, size_t size);

/**
 * Encrypt a message in OFB mode.
 *
 * @returns The actual number of bytes encrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t aes_encrypt_ofb(aes_state *state, const void *plaintext, void *ciphertext, size_t size);

/**
 * Encrypt a message in CFB mode with 8-bit synchronization.
 *
 * @returns The actual number of bytes encrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t aes_encrypt_cfb8(aes_state *state, const void *plaintext, void *ciphertext, size_t size);

/**
 * Encrypt a message in CFB mode with 128-bit synchronization.
 *
 * This function wraps aes_encrypt_cfb, since AES dictates 128-bit blocks.
 *
 * @returns The actual number of bytes encrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t aes_encrypt_cfb128(aes_state *state, const void *plaintext, void *ciphertext, size_t size);

/**
 * Encrypt a message in CFB mode with block synchronization.
 *
 * @returns The actual number of bytes encrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t aes_encrypt_cfb(aes_state *state, const void *plaintext, void *ciphertext, size_t size);

/**
 * Decrypt a message in ECB mode.
 *
 * @returns The actual number of bytes decrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t aes_decrypt_ecb(aes_state *state, const void *ciphertext, void *plaintext, size_t size);

/**
 * Decrypt a message in CBC mode.
 *
 * @returns The actual number of bytes decrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t aes_decrypt_cbc(aes_state *state, const void *ciphertext, void *plaintext, size_t size);

/**
 * Decrypt a message in OFB mode.
 *
 * @returns The actual number of bytes decrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t aes_decrypt_ofb(aes_state *state, const void *ciphertext, void *plaintext, size_t size);

/**
 * Decrypt a message in CFB mode with 8-bit synchronization.
 *
 * @returns The actual number of bytes decrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t aes_decrypt_cfb8(aes_state *state, const void *ciphertext, void *plaintext, size_t size);

/**
 * Decrypt a message in CFB mode with 128-bit synchronization.
 *
 * This function wraps aes_decrypt_cfb, since AES dictates 128-bit blocks.
 *
 * @returns The actual number of bytes decrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t aes_decrypt_cfb128(aes_state *state, const void *ciphertext, void *plaintext, size_t size);

/**
 * Decrypt a message in CFB mode with block synchronization.
 *
 * @returns The actual number of bytes decrypted.  This may be less than @a
 *          size if @a size is not a whole multiple of the block size.
 */
size_t aes_decrypt_cfb(aes_state *state, const void *ciphertext, void *plaintext, size_t size);

/******************************************************************************/

#ifdef __cplusplus
} /* extern "C" */
#endif

/******************************************************************************/

#endif /*RIJNDAEL_H_INCLUDED*/

/******************************************************************************\
 * EOF
\******************************************************************************/
