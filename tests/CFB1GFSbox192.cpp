#include "rijndael.h"
#include "catch.hpp"
#include <cstring>

TEST_CASE("CFB1GFSbox192-ENCRYPT-0", "[CFB1][GFSbox][192][ENCRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x1b,0x07,0x7a,0x6a,0xf4,0xb7,0xf9,0x82,0x29,0xde,0x78,0x6d,0x75,0x16,0xb6,0x39 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB1GFSbox192-ENCRYPT-1", "[CFB1][GFSbox][192][ENCRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x9c,0x2d,0x88,0x42,0xe5,0xf4,0x8f,0x57,0x64,0x82,0x05,0xd3,0x9a,0x23,0x9a,0xf1 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB1GFSbox192-ENCRYPT-2", "[CFB1][GFSbox][192][ENCRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0xbf,0xf5,0x25,0x10,0x09,0x5f,0x51,0x8e,0xcc,0xa6,0x0a,0xf4,0x20,0x54,0x44,0xbb };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB1GFSbox192-ENCRYPT-3", "[CFB1][GFSbox][192][ENCRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x51,0x71,0x97,0x83,0xd3,0x18,0x5a,0x53,0x5b,0xd7,0x5a,0xdc,0x65,0x07,0x1c,0xe1 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB1GFSbox192-ENCRYPT-4", "[CFB1][GFSbox][192][ENCRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x26,0xaa,0x49,0xdc,0xfe,0x76,0x29,0xa8,0x90,0x1a,0x69,0xa9,0x91,0x4e,0x6d,0xfd };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB1GFSbox192-ENCRYPT-5", "[CFB1][GFSbox][192][ENCRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x94,0x1a,0x47,0x73,0x05,0x82,0x24,0xe1,0xef,0x66,0xd1,0x0e,0x0a,0x6e,0xe7,0x82 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB1GFSbox192-DECRYPT-0", "[CFB1][GFSbox][192][DECRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x1b,0x07,0x7a,0x6a,0xf4,0xb7,0xf9,0x82,0x29,0xde,0x78,0x6d,0x75,0x16,0xb6,0x39 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB1GFSbox192-DECRYPT-1", "[CFB1][GFSbox][192][DECRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x9c,0x2d,0x88,0x42,0xe5,0xf4,0x8f,0x57,0x64,0x82,0x05,0xd3,0x9a,0x23,0x9a,0xf1 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB1GFSbox192-DECRYPT-2", "[CFB1][GFSbox][192][DECRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0xbf,0xf5,0x25,0x10,0x09,0x5f,0x51,0x8e,0xcc,0xa6,0x0a,0xf4,0x20,0x54,0x44,0xbb };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB1GFSbox192-DECRYPT-3", "[CFB1][GFSbox][192][DECRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x51,0x71,0x97,0x83,0xd3,0x18,0x5a,0x53,0x5b,0xd7,0x5a,0xdc,0x65,0x07,0x1c,0xe1 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB1GFSbox192-DECRYPT-4", "[CFB1][GFSbox][192][DECRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x26,0xaa,0x49,0xdc,0xfe,0x76,0x29,0xa8,0x90,0x1a,0x69,0xa9,0x91,0x4e,0x6d,0xfd };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

TEST_CASE("CFB1GFSbox192-DECRYPT-5", "[CFB1][GFSbox][192][DECRYPT]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x94,0x1a,0x47,0x73,0x05,0x82,0x24,0xe1,0xef,0x66,0xd1,0x0e,0x0a,0x6e,0xe7,0x82 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

