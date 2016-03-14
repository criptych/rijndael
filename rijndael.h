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

typedef enum rijndael_mode {
    RJ_MODE_ECB,
    RJ_MODE_CBC,
    RJ_MODE_OFB,
    RJ_MODE_CFB,
    RJ_MODE_CTR,
} rijndael_mode;

typedef enum rijndael_key_size {
    RJ_KEY_SIZE_128 = 4,
    RJ_KEY_SIZE_160 = 5,
    RJ_KEY_SIZE_192 = 6,
    RJ_KEY_SIZE_224 = 7,
    RJ_KEY_SIZE_256 = 8,
} rijndael_key_size;

typedef enum rijndael_block_size {
    RJ_BLOCK_SIZE_128 = 4,
    RJ_BLOCK_SIZE_160 = 5,
    RJ_BLOCK_SIZE_192 = 6,
    RJ_BLOCK_SIZE_224 = 7,
    RJ_BLOCK_SIZE_256 = 8,
} rijndael_block_size;

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
    /** Cipher mode, one of the rijndael_mode constants above. */
    uint8_t cipher_mode;
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
int rijndael_init(rijndael_state *state, const void *key, rijndael_key_size key_size, rijndael_block_size block_size);

/**
 * Initialize state with the given key, parameters, and IV.
 *
 * Used this function when encrypting or decrypting in CBC, OFB, or CFB modes.
 * The key and IV are copied into the state, so the original values do not need
 * to remain after this function returns.
 *
 * @returns Zero (0) if parameters are invalid, non-zero otherwise.
 */
int rijndael_init_iv(rijndael_state *state, const void *key, rijndael_key_size key_size, rijndael_block_size block_size, const void *iv);

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

typedef enum aes_mode {
    AES_MODE_ECB = RJ_MODE_ECB,
    AES_MODE_CBC = RJ_MODE_CBC,
    AES_MODE_OFB = RJ_MODE_OFB,
    AES_MODE_CFB = RJ_MODE_CFB,
    AES_MODE_CTR = RJ_MODE_CTR,
} aes_mode;

typedef enum aes_key_size {
    AES_KEY_SIZE_128 = RJ_KEY_SIZE_128,
    AES_KEY_SIZE_160 = RJ_KEY_SIZE_160,
    AES_KEY_SIZE_192 = RJ_KEY_SIZE_192,
    AES_KEY_SIZE_224 = RJ_KEY_SIZE_224,
    AES_KEY_SIZE_256 = RJ_KEY_SIZE_256,
} aes_key_size;

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
int aes_init(aes_state *state, const void *key, aes_key_size key_size);

/**
 * Initialize state with the given key, parameters, and IV.
 *
 * Used this function when encrypting or decrypting in CBC, OFB, or CFB modes.
 * The key and IV are copied into the state, so the original values do not need
 * to remain after this function returns.
 *
 * @returns Zero (0) if parameters are invalid, non-zero otherwise.
 */
int aes_init_iv(aes_state *state, const void *key, aes_key_size key_size, const void *iv);

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
