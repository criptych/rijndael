#include "rijndael.h"
#include "catch.hpp"
#include <cstring>

TEST_CASE("CBCKeySbox256-ENCRYPT-0", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0xc4,0x7b,0x02,0x94,0xdb,0xbb,0xee,0x0f,0xec,0x47,0x57,0xf2,0x2f,0xfe,0xee,0x35,0x87,0xca,0x47,0x30,0xc3,0xd3,0x3b,0x69,0x1d,0xf3,0x8b,0xab,0x07,0x6b,0xc5,0x58 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x46,0xf2,0xfb,0x34,0x2d,0x6f,0x0a,0xb4,0x77,0x47,0x6f,0xc5,0x01,0x24,0x2c,0x5f };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-1", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x28,0xd4,0x6c,0xff,0xa1,0x58,0x53,0x31,0x94,0x21,0x4a,0x91,0xe7,0x12,0xfc,0x2b,0x45,0xb5,0x18,0x07,0x66,0x75,0xaf,0xfd,0x91,0x0e,0xde,0xca,0x5f,0x41,0xac,0x64 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x4b,0xf3,0xb0,0xa6,0x9a,0xeb,0x66,0x57,0x79,0x4f,0x29,0x01,0xb1,0x44,0x0a,0xd4 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-2", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0xc1,0xcc,0x35,0x8b,0x44,0x99,0x09,0xa1,0x94,0x36,0xcf,0xbb,0x3f,0x85,0x2e,0xf8,0xbc,0xb5,0xed,0x12,0xac,0x70,0x58,0x32,0x5f,0x56,0xe6,0x09,0x9a,0xab,0x1a,0x1c };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x35,0x20,0x65,0x27,0x21,0x69,0xab,0xf9,0x85,0x68,0x43,0x92,0x7d,0x06,0x74,0xfd };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-3", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x98,0x4c,0xa7,0x5f,0x4e,0xe8,0xd7,0x06,0xf4,0x6c,0x2d,0x98,0xc0,0xbf,0x4a,0x45,0xf5,0xb0,0x0d,0x79,0x1c,0x2d,0xfe,0xb1,0x91,0xb5,0xed,0x8e,0x42,0x0f,0xd6,0x27 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x43,0x07,0x45,0x6a,0x9e,0x67,0x81,0x3b,0x45,0x2e,0x15,0xfa,0x8f,0xff,0xe3,0x98 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-4", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0xb4,0x3d,0x08,0xa4,0x47,0xac,0x86,0x09,0xba,0xad,0xae,0x4f,0xf1,0x29,0x18,0xb9,0xf6,0x8f,0xc1,0x65,0x3f,0x12,0x69,0x22,0x2f,0x12,0x39,0x81,0xde,0xd7,0xa9,0x2f };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x46,0x63,0x44,0x66,0x07,0x35,0x49,0x89,0x47,0x7a,0x5c,0x6f,0x0f,0x00,0x7e,0xf4 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-5", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x1d,0x85,0xa1,0x81,0xb5,0x4c,0xde,0x51,0xf0,0xe0,0x98,0x09,0x5b,0x29,0x62,0xfd,0xc9,0x3b,0x51,0xfe,0x9b,0x88,0x60,0x2b,0x3f,0x54,0x13,0x0b,0xf7,0x6a,0x5b,0xd9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x53,0x1c,0x2c,0x38,0x34,0x45,0x78,0xb8,0x4d,0x50,0xb3,0xc9,0x17,0xbb,0xb6,0xe1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-6", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0xdc,0x0e,0xba,0x1f,0x22,0x32,0xa7,0x87,0x9d,0xed,0x34,0xed,0x84,0x28,0xee,0xb8,0x76,0x9b,0x05,0x6b,0xba,0xf8,0xad,0x77,0xcb,0x65,0xc3,0x54,0x14,0x30,0xb4,0xcf };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xfc,0x6a,0xec,0x90,0x63,0x23,0x48,0x00,0x05,0xc5,0x8e,0x7e,0x1a,0xb0,0x04,0xad };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-7", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0xf8,0xbe,0x9b,0xa6,0x15,0xc5,0xa9,0x52,0xca,0xbb,0xca,0x24,0xf6,0x8f,0x85,0x93,0x03,0x96,0x24,0xd5,0x24,0xc8,0x16,0xac,0xda,0x2c,0x91,0x83,0xbd,0x91,0x7c,0xb9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xa3,0x94,0x4b,0x95,0xca,0x0b,0x52,0x04,0x35,0x84,0xef,0x02,0x15,0x19,0x26,0xa8 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-8", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x79,0x7f,0x8b,0x3d,0x17,0x6d,0xac,0x5b,0x7e,0x34,0xa2,0xd5,0x39,0xc4,0xef,0x36,0x7a,0x16,0xf8,0x63,0x5f,0x62,0x64,0x73,0x75,0x91,0xc5,0xc0,0x7b,0xf5,0x7a,0x3e };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xa7,0x42,0x89,0xfe,0x73,0xa4,0xc1,0x23,0xca,0x18,0x9e,0xa1,0xe1,0xb4,0x9a,0xd5 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-9", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x68,0x38,0xd4,0x0c,0xaf,0x92,0x77,0x49,0xc1,0x3f,0x03,0x29,0xd3,0x31,0xf4,0x48,0xe2,0x02,0xc7,0x3e,0xf5,0x2c,0x5f,0x73,0xa3,0x7c,0xa6,0x35,0xd4,0xc4,0x77,0x07 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xb9,0x1d,0x4e,0xa4,0x48,0x86,0x44,0xb5,0x6c,0xf0,0x81,0x2f,0xa7,0xfc,0xf5,0xfc };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-10", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0xcc,0xd1,0xbc,0x3c,0x65,0x9c,0xd3,0xc5,0x9b,0xc4,0x37,0x48,0x4e,0x3c,0x5c,0x72,0x44,0x41,0xda,0x8d,0x6e,0x90,0xce,0x55,0x6c,0xd5,0x7d,0x07,0x52,0x66,0x3b,0xbc };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x30,0x4f,0x81,0xab,0x61,0xa8,0x0c,0x2e,0x74,0x3b,0x94,0xd5,0x00,0x2a,0x12,0x6b };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-11", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x13,0x42,0x8b,0x5e,0x4c,0x00,0x5e,0x06,0x36,0xdd,0x33,0x84,0x05,0xd1,0x73,0xab,0x13,0x5d,0xec,0x2a,0x25,0xc2,0x2c,0x5d,0xf0,0x72,0x2d,0x69,0xdc,0xc4,0x38,0x87 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x64,0x9a,0x71,0x54,0x53,0x78,0xc7,0x83,0xe3,0x68,0xc9,0xad,0xe7,0x11,0x4f,0x6c };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-12", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x07,0xeb,0x03,0xa0,0x8d,0x29,0x1d,0x1b,0x07,0x40,0x8b,0xf3,0x51,0x2a,0xb4,0x0c,0x91,0x09,0x7a,0xc7,0x74,0x61,0xaa,0xd4,0xbb,0x85,0x96,0x47,0xf7,0x4f,0x00,0xee };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x47,0xcb,0x03,0x0d,0xa2,0xab,0x05,0x1d,0xfc,0x6c,0x4b,0xf6,0x91,0x0d,0x12,0xbb };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-13", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0x90,0x14,0x3a,0xe2,0x0c,0xd7,0x8c,0x5d,0x8e,0xbd,0xd6,0xcb,0x9d,0xc1,0x76,0x24,0x27,0xa9,0x6c,0x78,0xc6,0x39,0xbc,0xcc,0x41,0xa6,0x14,0x24,0x56,0x4e,0xaf,0xe1 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x79,0x8c,0x7c,0x00,0x5d,0xee,0x43,0x2b,0x2c,0x8e,0xa5,0xdf,0xa3,0x81,0xec,0xc3 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-14", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0xb7,0xa5,0x79,0x4d,0x52,0x73,0x74,0x75,0xd5,0x3d,0x5a,0x37,0x72,0x00,0x84,0x9b,0xe0,0x26,0x0a,0x67,0xa2,0xb2,0x2c,0xed,0x8b,0xbe,0xf1,0x28,0x82,0x27,0x0d,0x07 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x63,0x7c,0x31,0xdc,0x25,0x91,0xa0,0x76,0x36,0xf6,0x46,0xb7,0x2d,0xaa,0xbb,0xe7 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-ENCRYPT-15", "[CBC][KeySbox][256][ENCRYPT]") {
    const uint8_t KEY[] = { 0xfc,0xa0,0x2f,0x3d,0x50,0x11,0xcf,0xc5,0xc1,0xe2,0x31,0x65,0xd4,0x13,0xa0,0x49,0xd4,0x52,0x6a,0x99,0x18,0x27,0x42,0x4d,0x89,0x6f,0xe3,0x43,0x5e,0x0b,0xf6,0x8e };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x17,0x9a,0x49,0xc7,0x12,0x15,0x4b,0xbf,0xfb,0xe6,0xe7,0xa8,0x4a,0x18,0xe2,0x20 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-0", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0xc4,0x7b,0x02,0x94,0xdb,0xbb,0xee,0x0f,0xec,0x47,0x57,0xf2,0x2f,0xfe,0xee,0x35,0x87,0xca,0x47,0x30,0xc3,0xd3,0x3b,0x69,0x1d,0xf3,0x8b,0xab,0x07,0x6b,0xc5,0x58 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x46,0xf2,0xfb,0x34,0x2d,0x6f,0x0a,0xb4,0x77,0x47,0x6f,0xc5,0x01,0x24,0x2c,0x5f };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-1", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x28,0xd4,0x6c,0xff,0xa1,0x58,0x53,0x31,0x94,0x21,0x4a,0x91,0xe7,0x12,0xfc,0x2b,0x45,0xb5,0x18,0x07,0x66,0x75,0xaf,0xfd,0x91,0x0e,0xde,0xca,0x5f,0x41,0xac,0x64 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x4b,0xf3,0xb0,0xa6,0x9a,0xeb,0x66,0x57,0x79,0x4f,0x29,0x01,0xb1,0x44,0x0a,0xd4 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-2", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0xc1,0xcc,0x35,0x8b,0x44,0x99,0x09,0xa1,0x94,0x36,0xcf,0xbb,0x3f,0x85,0x2e,0xf8,0xbc,0xb5,0xed,0x12,0xac,0x70,0x58,0x32,0x5f,0x56,0xe6,0x09,0x9a,0xab,0x1a,0x1c };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x35,0x20,0x65,0x27,0x21,0x69,0xab,0xf9,0x85,0x68,0x43,0x92,0x7d,0x06,0x74,0xfd };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-3", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x98,0x4c,0xa7,0x5f,0x4e,0xe8,0xd7,0x06,0xf4,0x6c,0x2d,0x98,0xc0,0xbf,0x4a,0x45,0xf5,0xb0,0x0d,0x79,0x1c,0x2d,0xfe,0xb1,0x91,0xb5,0xed,0x8e,0x42,0x0f,0xd6,0x27 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x43,0x07,0x45,0x6a,0x9e,0x67,0x81,0x3b,0x45,0x2e,0x15,0xfa,0x8f,0xff,0xe3,0x98 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-4", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0xb4,0x3d,0x08,0xa4,0x47,0xac,0x86,0x09,0xba,0xad,0xae,0x4f,0xf1,0x29,0x18,0xb9,0xf6,0x8f,0xc1,0x65,0x3f,0x12,0x69,0x22,0x2f,0x12,0x39,0x81,0xde,0xd7,0xa9,0x2f };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x46,0x63,0x44,0x66,0x07,0x35,0x49,0x89,0x47,0x7a,0x5c,0x6f,0x0f,0x00,0x7e,0xf4 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-5", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x1d,0x85,0xa1,0x81,0xb5,0x4c,0xde,0x51,0xf0,0xe0,0x98,0x09,0x5b,0x29,0x62,0xfd,0xc9,0x3b,0x51,0xfe,0x9b,0x88,0x60,0x2b,0x3f,0x54,0x13,0x0b,0xf7,0x6a,0x5b,0xd9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x53,0x1c,0x2c,0x38,0x34,0x45,0x78,0xb8,0x4d,0x50,0xb3,0xc9,0x17,0xbb,0xb6,0xe1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-6", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0xdc,0x0e,0xba,0x1f,0x22,0x32,0xa7,0x87,0x9d,0xed,0x34,0xed,0x84,0x28,0xee,0xb8,0x76,0x9b,0x05,0x6b,0xba,0xf8,0xad,0x77,0xcb,0x65,0xc3,0x54,0x14,0x30,0xb4,0xcf };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xfc,0x6a,0xec,0x90,0x63,0x23,0x48,0x00,0x05,0xc5,0x8e,0x7e,0x1a,0xb0,0x04,0xad };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-7", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0xf8,0xbe,0x9b,0xa6,0x15,0xc5,0xa9,0x52,0xca,0xbb,0xca,0x24,0xf6,0x8f,0x85,0x93,0x03,0x96,0x24,0xd5,0x24,0xc8,0x16,0xac,0xda,0x2c,0x91,0x83,0xbd,0x91,0x7c,0xb9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xa3,0x94,0x4b,0x95,0xca,0x0b,0x52,0x04,0x35,0x84,0xef,0x02,0x15,0x19,0x26,0xa8 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-8", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x79,0x7f,0x8b,0x3d,0x17,0x6d,0xac,0x5b,0x7e,0x34,0xa2,0xd5,0x39,0xc4,0xef,0x36,0x7a,0x16,0xf8,0x63,0x5f,0x62,0x64,0x73,0x75,0x91,0xc5,0xc0,0x7b,0xf5,0x7a,0x3e };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xa7,0x42,0x89,0xfe,0x73,0xa4,0xc1,0x23,0xca,0x18,0x9e,0xa1,0xe1,0xb4,0x9a,0xd5 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-9", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x68,0x38,0xd4,0x0c,0xaf,0x92,0x77,0x49,0xc1,0x3f,0x03,0x29,0xd3,0x31,0xf4,0x48,0xe2,0x02,0xc7,0x3e,0xf5,0x2c,0x5f,0x73,0xa3,0x7c,0xa6,0x35,0xd4,0xc4,0x77,0x07 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xb9,0x1d,0x4e,0xa4,0x48,0x86,0x44,0xb5,0x6c,0xf0,0x81,0x2f,0xa7,0xfc,0xf5,0xfc };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-10", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0xcc,0xd1,0xbc,0x3c,0x65,0x9c,0xd3,0xc5,0x9b,0xc4,0x37,0x48,0x4e,0x3c,0x5c,0x72,0x44,0x41,0xda,0x8d,0x6e,0x90,0xce,0x55,0x6c,0xd5,0x7d,0x07,0x52,0x66,0x3b,0xbc };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x30,0x4f,0x81,0xab,0x61,0xa8,0x0c,0x2e,0x74,0x3b,0x94,0xd5,0x00,0x2a,0x12,0x6b };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-11", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x13,0x42,0x8b,0x5e,0x4c,0x00,0x5e,0x06,0x36,0xdd,0x33,0x84,0x05,0xd1,0x73,0xab,0x13,0x5d,0xec,0x2a,0x25,0xc2,0x2c,0x5d,0xf0,0x72,0x2d,0x69,0xdc,0xc4,0x38,0x87 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x64,0x9a,0x71,0x54,0x53,0x78,0xc7,0x83,0xe3,0x68,0xc9,0xad,0xe7,0x11,0x4f,0x6c };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-12", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x07,0xeb,0x03,0xa0,0x8d,0x29,0x1d,0x1b,0x07,0x40,0x8b,0xf3,0x51,0x2a,0xb4,0x0c,0x91,0x09,0x7a,0xc7,0x74,0x61,0xaa,0xd4,0xbb,0x85,0x96,0x47,0xf7,0x4f,0x00,0xee };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x47,0xcb,0x03,0x0d,0xa2,0xab,0x05,0x1d,0xfc,0x6c,0x4b,0xf6,0x91,0x0d,0x12,0xbb };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-13", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0x90,0x14,0x3a,0xe2,0x0c,0xd7,0x8c,0x5d,0x8e,0xbd,0xd6,0xcb,0x9d,0xc1,0x76,0x24,0x27,0xa9,0x6c,0x78,0xc6,0x39,0xbc,0xcc,0x41,0xa6,0x14,0x24,0x56,0x4e,0xaf,0xe1 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x79,0x8c,0x7c,0x00,0x5d,0xee,0x43,0x2b,0x2c,0x8e,0xa5,0xdf,0xa3,0x81,0xec,0xc3 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-14", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0xb7,0xa5,0x79,0x4d,0x52,0x73,0x74,0x75,0xd5,0x3d,0x5a,0x37,0x72,0x00,0x84,0x9b,0xe0,0x26,0x0a,0x67,0xa2,0xb2,0x2c,0xed,0x8b,0xbe,0xf1,0x28,0x82,0x27,0x0d,0x07 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x63,0x7c,0x31,0xdc,0x25,0x91,0xa0,0x76,0x36,0xf6,0x46,0xb7,0x2d,0xaa,0xbb,0xe7 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CBCKeySbox256-DECRYPT-15", "[CBC][KeySbox][256][DECRYPT]") {
    const uint8_t KEY[] = { 0xfc,0xa0,0x2f,0x3d,0x50,0x11,0xcf,0xc5,0xc1,0xe2,0x31,0x65,0xd4,0x13,0xa0,0x49,0xd4,0x52,0x6a,0x99,0x18,0x27,0x42,0x4d,0x89,0x6f,0xe3,0x43,0x5e,0x0b,0xf6,0x8e };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x17,0x9a,0x49,0xc7,0x12,0x15,0x4b,0xbf,0xfb,0xe6,0xe7,0xa8,0x4a,0x18,0xe2,0x20 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}
