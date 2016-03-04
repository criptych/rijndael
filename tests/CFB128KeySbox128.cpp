#include "rijndael.h"
#include "catch.hpp"
#include <cstring>

TEST_CASE("CFB128KeySbox128-ENCRYPT-0", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0x10,0xa5,0x88,0x69,0xd7,0x4b,0xe5,0xa3,0x74,0xcf,0x86,0x7c,0xfb,0x47,0x38,0x59 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x6d,0x25,0x1e,0x69,0x44,0xb0,0x51,0xe0,0x4e,0xaa,0x6f,0xb4,0xdb,0xf7,0x84,0x65 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-1", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0xca,0xea,0x65,0xcd,0xbb,0x75,0xe9,0x16,0x9e,0xcd,0x22,0xeb,0xe6,0xe5,0x46,0x75 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x6e,0x29,0x20,0x11,0x90,0x15,0x2d,0xf4,0xee,0x05,0x81,0x39,0xde,0xf6,0x10,0xbb };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-2", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0xa2,0xe2,0xfa,0x9b,0xaf,0x7d,0x20,0x82,0x2c,0xa9,0xf0,0x54,0x2f,0x76,0x4a,0x41 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xc3,0xb4,0x4b,0x95,0xd9,0xd2,0xf2,0x56,0x70,0xee,0xe9,0xa0,0xde,0x09,0x9f,0xa3 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-3", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0xb6,0x36,0x4a,0xc4,0xe1,0xde,0x1e,0x28,0x5e,0xaf,0x14,0x4a,0x24,0x15,0xf7,0xa0 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x5d,0x9b,0x05,0x57,0x8f,0xc9,0x44,0xb3,0xcf,0x1c,0xcf,0x0e,0x74,0x6c,0xd5,0x81 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-4", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0x64,0xcf,0x9c,0x7a,0xbc,0x50,0xb8,0x88,0xaf,0x65,0xf4,0x9d,0x52,0x19,0x44,0xb2 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xf7,0xef,0xc8,0x9d,0x5d,0xba,0x57,0x81,0x04,0x01,0x6c,0xe5,0xad,0x65,0x9c,0x05 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-5", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0x47,0xd6,0x74,0x2e,0xef,0xcc,0x04,0x65,0xdc,0x96,0x35,0x5e,0x85,0x1b,0x64,0xd9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x03,0x06,0x19,0x4f,0x66,0x6d,0x18,0x36,0x24,0xaa,0x23,0x0a,0x8b,0x26,0x4a,0xe7 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-6", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0x3e,0xb3,0x97,0x90,0x67,0x8c,0x56,0xbe,0xe3,0x4b,0xbc,0xde,0xcc,0xf6,0xcd,0xb5 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x85,0x80,0x75,0xd5,0x36,0xd7,0x9c,0xce,0xe5,0x71,0xf7,0xd7,0x20,0x4b,0x1f,0x67 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-7", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0x64,0x11,0x0a,0x92,0x4f,0x07,0x43,0xd5,0x00,0xcc,0xad,0xae,0x72,0xc1,0x34,0x27 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x35,0x87,0x0c,0x6a,0x57,0xe9,0xe9,0x23,0x14,0xbc,0xb8,0x08,0x7c,0xde,0x72,0xce };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-8", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0x18,0xd8,0x12,0x65,0x16,0xf8,0xa1,0x2a,0xb1,0xa3,0x6d,0x9f,0x04,0xd6,0x8e,0x51 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x6c,0x68,0xe9,0xbe,0x5e,0xc4,0x1e,0x22,0xc8,0x25,0xb7,0xc7,0xaf,0xfb,0x43,0x63 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-9", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0xf5,0x30,0x35,0x79,0x68,0x57,0x84,0x80,0xb3,0x98,0xa3,0xc2,0x51,0xcd,0x10,0x93 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xf5,0xdf,0x39,0x99,0x0f,0xc6,0x88,0xf1,0xb0,0x72,0x24,0xcc,0x03,0xe8,0x6c,0xea };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-10", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0xda,0x84,0x36,0x7f,0x32,0x5d,0x42,0xd6,0x01,0xb4,0x32,0x69,0x64,0x80,0x2e,0x8e };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xbb,0xa0,0x71,0xbc,0xb4,0x70,0xf8,0xf6,0x58,0x6e,0x5d,0x3a,0xdd,0x18,0xbc,0x66 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-11", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0xe3,0x7b,0x1c,0x6a,0xa2,0x84,0x6f,0x6f,0xdb,0x41,0x3f,0x23,0x8b,0x08,0x9f,0x23 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x43,0xc9,0xf7,0xe6,0x2f,0x5d,0x28,0x8b,0xb2,0x7a,0xa4,0x0e,0xf8,0xfe,0x1e,0xa8 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-12", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0x6c,0x00,0x2b,0x68,0x24,0x83,0xe0,0xca,0xbc,0xc7,0x31,0xc2,0x53,0xbe,0x56,0x74 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x35,0x80,0xd1,0x9c,0xff,0x44,0xf1,0x01,0x4a,0x7c,0x96,0x6a,0x69,0x05,0x9d,0xe5 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-13", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0x14,0x3a,0xe8,0xed,0x65,0x55,0xab,0xa9,0x61,0x10,0xab,0x58,0x89,0x3a,0x8a,0xe1 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x80,0x6d,0xa8,0x64,0xdd,0x29,0xd4,0x8d,0xea,0xfb,0xe7,0x64,0xf8,0x20,0x2a,0xef };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-14", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0xb6,0x94,0x18,0xa8,0x53,0x32,0x24,0x0d,0xc8,0x24,0x92,0x35,0x39,0x56,0xae,0x0c };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xa3,0x03,0xd9,0x40,0xde,0xd8,0xf0,0xba,0xff,0x6f,0x75,0x41,0x4c,0xac,0x52,0x43 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-15", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0x71,0xb5,0xc0,0x8a,0x19,0x93,0xe1,0x36,0x2e,0x4d,0x0c,0xe9,0xb2,0x2b,0x78,0xd5 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xc2,0xda,0xbd,0x11,0x7f,0x8a,0x3e,0xca,0xbf,0xbb,0x11,0xd1,0x21,0x94,0xd9,0xd0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-16", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0xe2,0x34,0xcd,0xca,0x26,0x06,0xb8,0x1f,0x29,0x40,0x8d,0x5f,0x6d,0xa2,0x12,0x06 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xff,0xf6,0x0a,0x47,0x40,0x08,0x6b,0x3b,0x9c,0x56,0x19,0x5b,0x98,0xd9,0x1a,0x7b };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-17", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0x13,0x23,0x7c,0x49,0x07,0x4a,0x3d,0xa0,0x78,0xdc,0x1d,0x82,0x8b,0xb7,0x8c,0x6f };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x81,0x46,0xa0,0x8e,0x23,0x57,0xf0,0xca,0xa3,0x0c,0xa8,0xc9,0x4d,0x1a,0x05,0x44 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-18", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0x30,0x71,0xa2,0xa4,0x8f,0xe6,0xcb,0xd0,0x4f,0x1a,0x12,0x90,0x98,0xe3,0x08,0xf8 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x4b,0x98,0xe0,0x6d,0x35,0x6d,0xeb,0x07,0xeb,0xb8,0x24,0xe5,0x71,0x3f,0x7b,0xe3 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-19", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0x90,0xf4,0x2e,0xc0,0xf6,0x83,0x85,0xf2,0xff,0xc5,0xdf,0xc0,0x3a,0x65,0x4d,0xce };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x7a,0x20,0xa5,0x3d,0x46,0x0f,0xc9,0xce,0x04,0x23,0xa7,0xa0,0x76,0x4c,0x6c,0xf2 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-ENCRYPT-20", "[CFB128][KeySbox][128][ENCRYPT]") {
    const uint8_t KEY[] = { 0xfe,0xbd,0x9a,0x24,0xd8,0xb6,0x5c,0x1c,0x78,0x7d,0x50,0xa4,0xed,0x36,0x19,0xa9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xf4,0xa7,0x0d,0x8a,0xf8,0x77,0xf9,0xb0,0x2b,0x4c,0x40,0xdf,0x57,0xd4,0x5b,0x17 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-0", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0x10,0xa5,0x88,0x69,0xd7,0x4b,0xe5,0xa3,0x74,0xcf,0x86,0x7c,0xfb,0x47,0x38,0x59 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x6d,0x25,0x1e,0x69,0x44,0xb0,0x51,0xe0,0x4e,0xaa,0x6f,0xb4,0xdb,0xf7,0x84,0x65 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-1", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0xca,0xea,0x65,0xcd,0xbb,0x75,0xe9,0x16,0x9e,0xcd,0x22,0xeb,0xe6,0xe5,0x46,0x75 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x6e,0x29,0x20,0x11,0x90,0x15,0x2d,0xf4,0xee,0x05,0x81,0x39,0xde,0xf6,0x10,0xbb };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-2", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0xa2,0xe2,0xfa,0x9b,0xaf,0x7d,0x20,0x82,0x2c,0xa9,0xf0,0x54,0x2f,0x76,0x4a,0x41 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xc3,0xb4,0x4b,0x95,0xd9,0xd2,0xf2,0x56,0x70,0xee,0xe9,0xa0,0xde,0x09,0x9f,0xa3 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-3", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0xb6,0x36,0x4a,0xc4,0xe1,0xde,0x1e,0x28,0x5e,0xaf,0x14,0x4a,0x24,0x15,0xf7,0xa0 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x5d,0x9b,0x05,0x57,0x8f,0xc9,0x44,0xb3,0xcf,0x1c,0xcf,0x0e,0x74,0x6c,0xd5,0x81 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-4", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0x64,0xcf,0x9c,0x7a,0xbc,0x50,0xb8,0x88,0xaf,0x65,0xf4,0x9d,0x52,0x19,0x44,0xb2 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xf7,0xef,0xc8,0x9d,0x5d,0xba,0x57,0x81,0x04,0x01,0x6c,0xe5,0xad,0x65,0x9c,0x05 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-5", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0x47,0xd6,0x74,0x2e,0xef,0xcc,0x04,0x65,0xdc,0x96,0x35,0x5e,0x85,0x1b,0x64,0xd9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x03,0x06,0x19,0x4f,0x66,0x6d,0x18,0x36,0x24,0xaa,0x23,0x0a,0x8b,0x26,0x4a,0xe7 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-6", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0x3e,0xb3,0x97,0x90,0x67,0x8c,0x56,0xbe,0xe3,0x4b,0xbc,0xde,0xcc,0xf6,0xcd,0xb5 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x85,0x80,0x75,0xd5,0x36,0xd7,0x9c,0xce,0xe5,0x71,0xf7,0xd7,0x20,0x4b,0x1f,0x67 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-7", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0x64,0x11,0x0a,0x92,0x4f,0x07,0x43,0xd5,0x00,0xcc,0xad,0xae,0x72,0xc1,0x34,0x27 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x35,0x87,0x0c,0x6a,0x57,0xe9,0xe9,0x23,0x14,0xbc,0xb8,0x08,0x7c,0xde,0x72,0xce };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-8", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0x18,0xd8,0x12,0x65,0x16,0xf8,0xa1,0x2a,0xb1,0xa3,0x6d,0x9f,0x04,0xd6,0x8e,0x51 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x6c,0x68,0xe9,0xbe,0x5e,0xc4,0x1e,0x22,0xc8,0x25,0xb7,0xc7,0xaf,0xfb,0x43,0x63 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-9", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0xf5,0x30,0x35,0x79,0x68,0x57,0x84,0x80,0xb3,0x98,0xa3,0xc2,0x51,0xcd,0x10,0x93 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xf5,0xdf,0x39,0x99,0x0f,0xc6,0x88,0xf1,0xb0,0x72,0x24,0xcc,0x03,0xe8,0x6c,0xea };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-10", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0xda,0x84,0x36,0x7f,0x32,0x5d,0x42,0xd6,0x01,0xb4,0x32,0x69,0x64,0x80,0x2e,0x8e };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xbb,0xa0,0x71,0xbc,0xb4,0x70,0xf8,0xf6,0x58,0x6e,0x5d,0x3a,0xdd,0x18,0xbc,0x66 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-11", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0xe3,0x7b,0x1c,0x6a,0xa2,0x84,0x6f,0x6f,0xdb,0x41,0x3f,0x23,0x8b,0x08,0x9f,0x23 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x43,0xc9,0xf7,0xe6,0x2f,0x5d,0x28,0x8b,0xb2,0x7a,0xa4,0x0e,0xf8,0xfe,0x1e,0xa8 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-12", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0x6c,0x00,0x2b,0x68,0x24,0x83,0xe0,0xca,0xbc,0xc7,0x31,0xc2,0x53,0xbe,0x56,0x74 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x35,0x80,0xd1,0x9c,0xff,0x44,0xf1,0x01,0x4a,0x7c,0x96,0x6a,0x69,0x05,0x9d,0xe5 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-13", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0x14,0x3a,0xe8,0xed,0x65,0x55,0xab,0xa9,0x61,0x10,0xab,0x58,0x89,0x3a,0x8a,0xe1 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x80,0x6d,0xa8,0x64,0xdd,0x29,0xd4,0x8d,0xea,0xfb,0xe7,0x64,0xf8,0x20,0x2a,0xef };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-14", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0xb6,0x94,0x18,0xa8,0x53,0x32,0x24,0x0d,0xc8,0x24,0x92,0x35,0x39,0x56,0xae,0x0c };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xa3,0x03,0xd9,0x40,0xde,0xd8,0xf0,0xba,0xff,0x6f,0x75,0x41,0x4c,0xac,0x52,0x43 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-15", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0x71,0xb5,0xc0,0x8a,0x19,0x93,0xe1,0x36,0x2e,0x4d,0x0c,0xe9,0xb2,0x2b,0x78,0xd5 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xc2,0xda,0xbd,0x11,0x7f,0x8a,0x3e,0xca,0xbf,0xbb,0x11,0xd1,0x21,0x94,0xd9,0xd0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-16", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0xe2,0x34,0xcd,0xca,0x26,0x06,0xb8,0x1f,0x29,0x40,0x8d,0x5f,0x6d,0xa2,0x12,0x06 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xff,0xf6,0x0a,0x47,0x40,0x08,0x6b,0x3b,0x9c,0x56,0x19,0x5b,0x98,0xd9,0x1a,0x7b };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-17", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0x13,0x23,0x7c,0x49,0x07,0x4a,0x3d,0xa0,0x78,0xdc,0x1d,0x82,0x8b,0xb7,0x8c,0x6f };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x81,0x46,0xa0,0x8e,0x23,0x57,0xf0,0xca,0xa3,0x0c,0xa8,0xc9,0x4d,0x1a,0x05,0x44 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-18", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0x30,0x71,0xa2,0xa4,0x8f,0xe6,0xcb,0xd0,0x4f,0x1a,0x12,0x90,0x98,0xe3,0x08,0xf8 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x4b,0x98,0xe0,0x6d,0x35,0x6d,0xeb,0x07,0xeb,0xb8,0x24,0xe5,0x71,0x3f,0x7b,0xe3 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-19", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0x90,0xf4,0x2e,0xc0,0xf6,0x83,0x85,0xf2,0xff,0xc5,0xdf,0xc0,0x3a,0x65,0x4d,0xce };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x7a,0x20,0xa5,0x3d,0x46,0x0f,0xc9,0xce,0x04,0x23,0xa7,0xa0,0x76,0x4c,0x6c,0xf2 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB128KeySbox128-DECRYPT-20", "[CFB128][KeySbox][128][DECRYPT]") {
    const uint8_t KEY[] = { 0xfe,0xbd,0x9a,0x24,0xd8,0xb6,0x5c,0x1c,0x78,0x7d,0x50,0xa4,0xed,0x36,0x19,0xa9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t CIPHERTEXT[] = { 0xf4,0xa7,0x0d,0x8a,0xf8,0x77,0xf9,0xb0,0x2b,0x4c,0x40,0xdf,0x57,0xd4,0x5b,0x17 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

