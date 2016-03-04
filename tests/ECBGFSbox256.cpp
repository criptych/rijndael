#include "rijndael.h"
#include "catch.hpp"
#include <cstring>

TEST_CASE("ECBGFSbox256-ENCRYPT-0", "[ECB][GFSbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x01,0x47,0x30,0xf8,0x0a,0xc6,0x25,0xfe,0x84,0xf0,0x26,0xc6,0x0b,0xfd,0x54,0x7d };
    const uint8_t CIPHERTEXT[] = { 0x5c,0x9d,0x84,0x4e,0xd4,0x6f,0x98,0x85,0x08,0x5e,0x5d,0x6a,0x4f,0x94,0xc7,0xd7 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("ECBGFSbox256-ENCRYPT-1", "[ECB][GFSbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0b,0x24,0xaf,0x36,0x19,0x3c,0xe4,0x66,0x5f,0x28,0x25,0xd7,0xb4,0x74,0x9c,0x98 };
    const uint8_t CIPHERTEXT[] = { 0xa9,0xff,0x75,0xbd,0x7c,0xf6,0x61,0x3d,0x37,0x31,0xc7,0x7c,0x3b,0x6d,0x0c,0x04 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("ECBGFSbox256-ENCRYPT-2", "[ECB][GFSbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x76,0x1c,0x1f,0xe4,0x1a,0x18,0xac,0xf2,0x0d,0x24,0x16,0x50,0x61,0x1d,0x90,0xf1 };
    const uint8_t CIPHERTEXT[] = { 0x62,0x3a,0x52,0xfc,0xea,0x5d,0x44,0x3e,0x48,0xd9,0x18,0x1a,0xb3,0x2c,0x74,0x21 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("ECBGFSbox256-ENCRYPT-3", "[ECB][GFSbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x8a,0x56,0x07,0x69,0xd6,0x05,0x86,0x8a,0xd8,0x0d,0x81,0x9b,0xdb,0xa0,0x37,0x71 };
    const uint8_t CIPHERTEXT[] = { 0x38,0xf2,0xc7,0xae,0x10,0x61,0x24,0x15,0xd2,0x7c,0xa1,0x90,0xd2,0x7d,0xa8,0xb4 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("ECBGFSbox256-ENCRYPT-4", "[ECB][GFSbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x91,0xfb,0xef,0x2d,0x15,0xa9,0x78,0x16,0x06,0x0b,0xee,0x1f,0xea,0xa4,0x9a,0xfe };
    const uint8_t CIPHERTEXT[] = { 0x1b,0xc7,0x04,0xf1,0xbc,0xe1,0x35,0xce,0xb8,0x10,0x34,0x1b,0x21,0x6d,0x7a,0xbe };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("ECBGFSbox256-DECRYPT-0", "[ECB][GFSbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x01,0x47,0x30,0xf8,0x0a,0xc6,0x25,0xfe,0x84,0xf0,0x26,0xc6,0x0b,0xfd,0x54,0x7d };
    const uint8_t CIPHERTEXT[] = { 0x5c,0x9d,0x84,0x4e,0xd4,0x6f,0x98,0x85,0x08,0x5e,0x5d,0x6a,0x4f,0x94,0xc7,0xd7 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("ECBGFSbox256-DECRYPT-1", "[ECB][GFSbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0b,0x24,0xaf,0x36,0x19,0x3c,0xe4,0x66,0x5f,0x28,0x25,0xd7,0xb4,0x74,0x9c,0x98 };
    const uint8_t CIPHERTEXT[] = { 0xa9,0xff,0x75,0xbd,0x7c,0xf6,0x61,0x3d,0x37,0x31,0xc7,0x7c,0x3b,0x6d,0x0c,0x04 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("ECBGFSbox256-DECRYPT-2", "[ECB][GFSbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x76,0x1c,0x1f,0xe4,0x1a,0x18,0xac,0xf2,0x0d,0x24,0x16,0x50,0x61,0x1d,0x90,0xf1 };
    const uint8_t CIPHERTEXT[] = { 0x62,0x3a,0x52,0xfc,0xea,0x5d,0x44,0x3e,0x48,0xd9,0x18,0x1a,0xb3,0x2c,0x74,0x21 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("ECBGFSbox256-DECRYPT-3", "[ECB][GFSbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x8a,0x56,0x07,0x69,0xd6,0x05,0x86,0x8a,0xd8,0x0d,0x81,0x9b,0xdb,0xa0,0x37,0x71 };
    const uint8_t CIPHERTEXT[] = { 0x38,0xf2,0xc7,0xae,0x10,0x61,0x24,0x15,0xd2,0x7c,0xa1,0x90,0xd2,0x7d,0xa8,0xb4 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("ECBGFSbox256-DECRYPT-4", "[ECB][GFSbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x91,0xfb,0xef,0x2d,0x15,0xa9,0x78,0x16,0x06,0x0b,0xee,0x1f,0xea,0xa4,0x9a,0xfe };
    const uint8_t CIPHERTEXT[] = { 0x1b,0xc7,0x04,0xf1,0xbc,0xe1,0x35,0xce,0xb8,0x10,0x34,0x1b,0x21,0x6d,0x7a,0xbe };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

