#include "rijndael.h"
#include "catch.hpp"
#include <cstring>

static inline std::string buf2str(const uint8_t *buf, size_t len) {
    std::ostringstream ss; ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(buf[i]) << ' ';
    }
    return ss.str();
}

TEST_CASE("CFB1GFSbox128-ENCRYPT-0", "[CFB1][GFSbox][128][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0xf3,0x44,0x81,0xec,0x3c,0xc6,0x27,0xba,0xcd,0x5d,0xc3,0xfb,0x08,0xf2,0x73,0xe6 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-ENCRYPT-1", "[CFB1][GFSbox][128][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x97,0x98,0xc4,0x64,0x0b,0xad,0x75,0xc7,0xc3,0x22,0x7d,0xb9,0x10,0x17,0x4e,0x72 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-ENCRYPT-2", "[CFB1][GFSbox][128][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x96,0xab,0x5c,0x2f,0xf6,0x12,0xd9,0xdf,0xaa,0xe8,0xc3,0x1f,0x30,0xc4,0x21,0x68 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-ENCRYPT-3", "[CFB1][GFSbox][128][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x6a,0x11,0x8a,0x87,0x45,0x19,0xe6,0x4e,0x99,0x63,0x79,0x8a,0x50,0x3f,0x1d,0x35 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-ENCRYPT-4", "[CFB1][GFSbox][128][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0xcb,0x9f,0xce,0xec,0x81,0x28,0x6c,0xa3,0xe9,0x89,0xbd,0x97,0x9b,0x0c,0xb2,0x84 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-ENCRYPT-5", "[CFB1][GFSbox][128][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0xb2,0x6a,0xeb,0x18,0x74,0xe4,0x7c,0xa8,0x35,0x8f,0xf2,0x23,0x78,0xf0,0x91,0x44 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-ENCRYPT-6", "[CFB1][GFSbox][128][ENCRYPT][n6]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x58,0xc8,0xe0,0x0b,0x26,0x31,0x68,0x6d,0x54,0xea,0xb8,0x4b,0x91,0xf0,0xac,0xa1 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-DECRYPT-0", "[CFB1][GFSbox][128][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0xf3,0x44,0x81,0xec,0x3c,0xc6,0x27,0xba,0xcd,0x5d,0xc3,0xfb,0x08,0xf2,0x73,0xe6 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-DECRYPT-1", "[CFB1][GFSbox][128][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x97,0x98,0xc4,0x64,0x0b,0xad,0x75,0xc7,0xc3,0x22,0x7d,0xb9,0x10,0x17,0x4e,0x72 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-DECRYPT-2", "[CFB1][GFSbox][128][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x96,0xab,0x5c,0x2f,0xf6,0x12,0xd9,0xdf,0xaa,0xe8,0xc3,0x1f,0x30,0xc4,0x21,0x68 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-DECRYPT-3", "[CFB1][GFSbox][128][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x6a,0x11,0x8a,0x87,0x45,0x19,0xe6,0x4e,0x99,0x63,0x79,0x8a,0x50,0x3f,0x1d,0x35 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-DECRYPT-4", "[CFB1][GFSbox][128][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0xcb,0x9f,0xce,0xec,0x81,0x28,0x6c,0xa3,0xe9,0x89,0xbd,0x97,0x9b,0x0c,0xb2,0x84 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-DECRYPT-5", "[CFB1][GFSbox][128][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0xb2,0x6a,0xeb,0x18,0x74,0xe4,0x7c,0xa8,0x35,0x8f,0xf2,0x23,0x78,0xf0,0x91,0x44 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1GFSbox128-DECRYPT-6", "[CFB1][GFSbox][128][DECRYPT][n6]") {
    const uint8_t KEY[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t IV[] = { 0x58,0xc8,0xe0,0x0b,0x26,0x31,0x68,0x6d,0x54,0xea,0xb8,0x4b,0x91,0xf0,0xac,0xa1 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

