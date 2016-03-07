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

TEST_CASE("CFB1MCT128-ENCRYPT-0", "[CFB1][MCT][128][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0x36,0xc6,0xef,0x5e,0x03,0x2c,0x94,0x21,0xde,0x69,0xb4,0x7e,0xd3,0xa9,0xd9,0xa4 };
    const uint8_t IV[] = { 0x48,0xc0,0x53,0x98,0x01,0x90,0x35,0x3f,0x64,0x99,0xbf,0xef,0xac,0xfd,0x1d,0x73 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-1", "[CFB1][MCT][128][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0xfa,0x36,0xc5,0xa2,0xc5,0x76,0x32,0xc1,0x52,0xd8,0xb9,0xd2,0x01,0x76,0xb5,0xc4 };
    const uint8_t IV[] = { 0xcc,0xf0,0x2a,0xfc,0xc6,0x5a,0xa6,0xe0,0x8c,0xb1,0x0d,0xac,0xd2,0xdf,0x6c,0x60 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-2", "[CFB1][MCT][128][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0x7d,0x2e,0x9a,0x24,0xb0,0x11,0x25,0xb7,0xce,0x1e,0x9b,0x70,0x00,0x8b,0xf4,0x6a };
    const uint8_t IV[] = { 0x87,0x18,0x5f,0x86,0x75,0x67,0x17,0x76,0x9c,0xc6,0x22,0xa2,0x01,0xfd,0x41,0xae };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-3", "[CFB1][MCT][128][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0xf8,0x00,0x47,0x2b,0xdf,0xb8,0x59,0xaa,0x8d,0x90,0x5f,0xf1,0x03,0x52,0x99,0x60 };
    const uint8_t IV[] = { 0x85,0x2e,0xdd,0x0f,0x6f,0xa9,0x7c,0x1d,0x43,0x8e,0xc4,0x81,0x03,0xd9,0x6d,0x0a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-4", "[CFB1][MCT][128][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0x6e,0xfc,0x04,0x1d,0x50,0x5e,0x08,0x01,0xf4,0x8b,0x66,0x0a,0x89,0x93,0x1a,0x50 };
    const uint8_t IV[] = { 0x96,0xfc,0x43,0x36,0x8f,0xe6,0x51,0xab,0x79,0x1b,0x39,0xfb,0x8a,0xc1,0x83,0x30 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-5", "[CFB1][MCT][128][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0xd3,0x49,0xa7,0x99,0x9c,0xcd,0x13,0x7b,0xeb,0x2d,0x69,0xa3,0xec,0x00,0x26,0x14 };
    const uint8_t IV[] = { 0xbd,0xb5,0xa3,0x84,0xcc,0x93,0x1b,0x7a,0x1f,0xa6,0x0f,0xa9,0x65,0x93,0x3c,0x44 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-6", "[CFB1][MCT][128][ENCRYPT][n6]") {
    const uint8_t KEY[] = { 0x35,0x23,0xbb,0xc0,0x65,0x62,0x3f,0x4e,0x79,0x3b,0xc0,0x8f,0x51,0x92,0xd9,0xd3 };
    const uint8_t IV[] = { 0xe6,0x6a,0x1c,0x59,0xf9,0xaf,0x2c,0x35,0x92,0x16,0xa9,0x2c,0xbd,0x92,0xff,0xc7 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-7", "[CFB1][MCT][128][ENCRYPT][n7]") {
    const uint8_t KEY[] = { 0x3f,0x1c,0xa5,0xef,0x56,0x4b,0xbf,0xc4,0x9b,0x61,0xbd,0x96,0xb4,0x62,0xaf,0xc4 };
    const uint8_t IV[] = { 0x0a,0x3f,0x1e,0x2f,0x33,0x29,0x80,0x8a,0xe2,0x5a,0x7d,0x19,0xe5,0xf0,0x76,0x17 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-8", "[CFB1][MCT][128][ENCRYPT][n8]") {
    const uint8_t KEY[] = { 0xc9,0x82,0x74,0x37,0xb1,0x99,0x59,0xcb,0x07,0x01,0xde,0xfe,0x3f,0x93,0xc5,0x10 };
    const uint8_t IV[] = { 0xf6,0x9e,0xd1,0xd8,0xe7,0xd2,0xe6,0x0f,0x9c,0x60,0x63,0x68,0x8b,0xf1,0x6a,0xd4 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-9", "[CFB1][MCT][128][ENCRYPT][n9]") {
    const uint8_t KEY[] = { 0xf4,0xbd,0xd9,0x46,0xbb,0x30,0xea,0x59,0xd4,0xd4,0x13,0x8e,0x8f,0x29,0x20,0xc9 };
    const uint8_t IV[] = { 0x3d,0x3f,0xad,0x71,0x0a,0xa9,0xb3,0x92,0xd3,0xd5,0xcd,0x70,0xb0,0xba,0xe5,0xd9 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-10", "[CFB1][MCT][128][ENCRYPT][n10]") {
    const uint8_t KEY[] = { 0xd0,0x74,0x67,0x0b,0x7c,0x2b,0xc8,0x63,0xbd,0x50,0x0d,0x63,0x4b,0x79,0x33,0xb6 };
    const uint8_t IV[] = { 0x24,0xc9,0xbe,0x4d,0xc7,0x1b,0x22,0x3a,0x69,0x84,0x1e,0xed,0xc4,0x50,0x13,0x7f };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-11", "[CFB1][MCT][128][ENCRYPT][n11]") {
    const uint8_t KEY[] = { 0x25,0xb8,0x3d,0xc9,0xae,0xb0,0xa8,0x22,0x3a,0x4d,0x88,0x4a,0x48,0xb5,0xec,0xfa };
    const uint8_t IV[] = { 0xf5,0xcc,0x5a,0xc2,0xd2,0x9b,0x60,0x41,0x87,0x1d,0x85,0x29,0x03,0xcc,0xdf,0x4c };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-12", "[CFB1][MCT][128][ENCRYPT][n12]") {
    const uint8_t KEY[] = { 0x16,0x89,0x8c,0x80,0xb1,0x41,0x2d,0xc7,0x3f,0x4e,0x77,0x28,0x71,0xab,0xb6,0xf8 };
    const uint8_t IV[] = { 0x33,0x31,0xb1,0x49,0x1f,0xf1,0x85,0xe5,0x05,0x03,0xff,0x62,0x39,0x1e,0x5a,0x02 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-13", "[CFB1][MCT][128][ENCRYPT][n13]") {
    const uint8_t KEY[] = { 0xbd,0xfa,0xa5,0x76,0x50,0x18,0x07,0x3e,0x00,0xde,0x6b,0x05,0x11,0xc0,0x7f,0xbb };
    const uint8_t IV[] = { 0xab,0x73,0x29,0xf6,0xe1,0x59,0x2a,0xf9,0x3f,0x90,0x1c,0x2d,0x60,0x6b,0xc9,0x43 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-14", "[CFB1][MCT][128][ENCRYPT][n14]") {
    const uint8_t KEY[] = { 0xba,0xdd,0x74,0xee,0xd6,0x7b,0x61,0x91,0x57,0xae,0x5c,0xe2,0xf4,0x9e,0xbf,0xc8 };
    const uint8_t IV[] = { 0x07,0x27,0xd1,0x98,0x86,0x63,0x66,0xaf,0x57,0x70,0x37,0xe7,0xe5,0x5e,0xc0,0x73 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-15", "[CFB1][MCT][128][ENCRYPT][n15]") {
    const uint8_t KEY[] = { 0xb0,0x78,0x29,0x73,0x69,0x82,0x0c,0x8a,0xab,0x99,0x65,0xba,0xcb,0x5f,0x82,0xe5 };
    const uint8_t IV[] = { 0x0a,0xa5,0x5d,0x9d,0xbf,0xf9,0x6d,0x1b,0xfc,0x37,0x39,0x58,0x3f,0xc1,0x3d,0x2d };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-16", "[CFB1][MCT][128][ENCRYPT][n16]") {
    const uint8_t KEY[] = { 0x1c,0x4e,0x58,0xda,0x10,0xfd,0x6a,0x69,0xe1,0x01,0x8b,0xeb,0x57,0x6b,0x1f,0x04 };
    const uint8_t IV[] = { 0xac,0x36,0x71,0xa9,0x79,0x7f,0x66,0xe3,0x4a,0x98,0xee,0x51,0x9c,0x34,0x9d,0xe1 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-17", "[CFB1][MCT][128][ENCRYPT][n17]") {
    const uint8_t KEY[] = { 0x88,0x2b,0x67,0xb7,0x1e,0x53,0xcc,0x5f,0xed,0xac,0x60,0xdb,0xac,0x22,0xeb,0xa2 };
    const uint8_t IV[] = { 0x94,0x65,0x3f,0x6d,0x0e,0xae,0xa6,0x36,0x0c,0xad,0xeb,0x30,0xfb,0x49,0xf4,0xa6 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-18", "[CFB1][MCT][128][ENCRYPT][n18]") {
    const uint8_t KEY[] = { 0x7e,0x2a,0x05,0x81,0xc0,0x5f,0xec,0x59,0x03,0xec,0x36,0xa1,0x6a,0xe3,0x4e,0x9f };
    const uint8_t IV[] = { 0xf6,0x01,0x62,0x36,0xde,0x0c,0x20,0x06,0xee,0x40,0x56,0x7a,0xc6,0xc1,0xa5,0x3d };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-19", "[CFB1][MCT][128][ENCRYPT][n19]") {
    const uint8_t KEY[] = { 0xf6,0xc3,0x66,0x9b,0x6c,0xc0,0xf1,0x25,0x36,0x66,0x59,0x9e,0x27,0xaf,0xdc,0x40 };
    const uint8_t IV[] = { 0x88,0xe9,0x63,0x1a,0xac,0x9f,0x1d,0x7c,0x35,0x8a,0x6f,0x3f,0x4d,0x4c,0x92,0xdf };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-20", "[CFB1][MCT][128][ENCRYPT][n20]") {
    const uint8_t KEY[] = { 0x86,0x4d,0x2e,0xa4,0x52,0x69,0x69,0x7f,0x5f,0xdc,0x66,0x96,0x84,0x4e,0xd2,0x24 };
    const uint8_t IV[] = { 0x70,0x8e,0x48,0x3f,0x3e,0xa9,0x98,0x5a,0x69,0xba,0x3f,0x08,0xa3,0xe1,0x0e,0x64 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-21", "[CFB1][MCT][128][ENCRYPT][n21]") {
    const uint8_t KEY[] = { 0x1b,0x2e,0x35,0x37,0x82,0x2b,0xda,0x1b,0xa8,0x72,0xa3,0x17,0x4b,0x5b,0xd8,0x76 };
    const uint8_t IV[] = { 0x9d,0x63,0x1b,0x93,0xd0,0x42,0xb3,0x64,0xf7,0xae,0xc5,0x81,0xcf,0x15,0x0a,0x52 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-22", "[CFB1][MCT][128][ENCRYPT][n22]") {
    const uint8_t KEY[] = { 0xf6,0xb8,0x7b,0x33,0x46,0xd4,0xc6,0xb6,0x7b,0x9d,0xd6,0xe8,0xcf,0x08,0x69,0x3e };
    const uint8_t IV[] = { 0xed,0x96,0x4e,0x04,0xc4,0xff,0x1c,0xad,0xd3,0xef,0x75,0xff,0x84,0x53,0xb1,0x48 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-23", "[CFB1][MCT][128][ENCRYPT][n23]") {
    const uint8_t KEY[] = { 0x6d,0x5c,0xf8,0x1a,0xe7,0xd0,0x4f,0x3e,0x70,0xb9,0xe4,0xa9,0xaa,0x5b,0x6f,0xef };
    const uint8_t IV[] = { 0x9b,0xe4,0x83,0x29,0xa1,0x04,0x89,0x88,0x0b,0x24,0x32,0x41,0x65,0x53,0x06,0xd1 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-24", "[CFB1][MCT][128][ENCRYPT][n24]") {
    const uint8_t KEY[] = { 0x98,0x52,0xae,0x91,0x0a,0x17,0xbe,0xa5,0x21,0x5f,0x88,0x21,0xef,0x79,0x26,0xe5 };
    const uint8_t IV[] = { 0xf5,0x0e,0x56,0x8b,0xed,0xc7,0xf1,0x9b,0x51,0xe6,0x6c,0x88,0x45,0x22,0x49,0x0a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-25", "[CFB1][MCT][128][ENCRYPT][n25]") {
    const uint8_t KEY[] = { 0xca,0xcc,0xe8,0x5d,0x2e,0x17,0x94,0x68,0x83,0xcd,0x68,0x58,0x32,0x21,0x16,0x80 };
    const uint8_t IV[] = { 0x52,0x9e,0x46,0xcc,0x24,0x00,0x2a,0xcd,0xa2,0x92,0xe0,0x79,0xdd,0x58,0x30,0x65 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-26", "[CFB1][MCT][128][ENCRYPT][n26]") {
    const uint8_t KEY[] = { 0xa9,0x70,0x25,0xdc,0x25,0x7c,0x12,0x28,0x89,0x1a,0xd1,0x6c,0xf8,0xb8,0x14,0xda };
    const uint8_t IV[] = { 0x63,0xbc,0xcd,0x81,0x0b,0x6b,0x86,0x40,0x0a,0xd7,0xb9,0x34,0xca,0x99,0x02,0x5a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-27", "[CFB1][MCT][128][ENCRYPT][n27]") {
    const uint8_t KEY[] = { 0xa7,0xfd,0x6a,0x06,0xa7,0xdc,0x97,0xbe,0xa4,0x6b,0x8b,0xcd,0xe9,0x94,0xb1,0xd0 };
    const uint8_t IV[] = { 0x0e,0x8d,0x4f,0xda,0x82,0xa0,0x85,0x96,0x2d,0x71,0x5a,0xa1,0x11,0x2c,0xa5,0x0a };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-28", "[CFB1][MCT][128][ENCRYPT][n28]") {
    const uint8_t KEY[] = { 0x18,0x67,0xb7,0x52,0xc5,0x7e,0x47,0x80,0xa2,0xa7,0x61,0x9d,0xcb,0x96,0x3e,0xa5 };
    const uint8_t IV[] = { 0xbf,0x9a,0xdd,0x54,0x62,0xa2,0xd0,0x3e,0x06,0xcc,0xea,0x50,0x22,0x02,0x8f,0x75 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-29", "[CFB1][MCT][128][ENCRYPT][n29]") {
    const uint8_t KEY[] = { 0x28,0xa0,0x18,0x91,0x5f,0x43,0x00,0x0b,0x2d,0xd0,0x2c,0x18,0x98,0x86,0xc6,0x3a };
    const uint8_t IV[] = { 0x30,0xc7,0xaf,0xc3,0x9a,0x3d,0x47,0x8b,0x8f,0x77,0x4d,0x85,0x53,0x10,0xf8,0x9f };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-30", "[CFB1][MCT][128][ENCRYPT][n30]") {
    const uint8_t KEY[] = { 0xa4,0xcd,0xd6,0xe0,0xa3,0xa5,0x60,0xde,0x69,0x78,0xaf,0x8d,0x5b,0x97,0x4f,0x6c };
    const uint8_t IV[] = { 0x8c,0x6d,0xce,0x71,0xfc,0xe6,0x60,0xd5,0x44,0xa8,0x83,0x95,0xc3,0x11,0x89,0x56 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-31", "[CFB1][MCT][128][ENCRYPT][n31]") {
    const uint8_t KEY[] = { 0x59,0xf4,0xcf,0x75,0x01,0x6c,0xb9,0xdb,0xc4,0x1b,0xaa,0x3b,0xf9,0x0e,0xd5,0x19 };
    const uint8_t IV[] = { 0xfd,0x39,0x19,0x95,0xa2,0xc9,0xd9,0x05,0xad,0x63,0x05,0xb6,0xa2,0x99,0x9a,0x75 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-32", "[CFB1][MCT][128][ENCRYPT][n32]") {
    const uint8_t KEY[] = { 0x36,0x3c,0x5e,0x36,0xe9,0x90,0xfa,0xc2,0x75,0x05,0x0e,0x93,0x2b,0x72,0xd2,0x81 };
    const uint8_t IV[] = { 0x6f,0xc8,0x91,0x43,0xe8,0xfc,0x43,0x19,0xb1,0x1e,0xa4,0xa8,0xd2,0x7c,0x07,0x98 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-33", "[CFB1][MCT][128][ENCRYPT][n33]") {
    const uint8_t KEY[] = { 0x13,0xf1,0x3d,0xd1,0x7a,0x6f,0x7d,0x64,0x23,0x47,0xd1,0x09,0x2b,0x6f,0xb6,0x8a };
    const uint8_t IV[] = { 0x25,0xcd,0x63,0xe7,0x93,0xff,0x87,0xa6,0x56,0x42,0xdf,0x9a,0x00,0x1d,0x64,0x0b };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-34", "[CFB1][MCT][128][ENCRYPT][n34]") {
    const uint8_t KEY[] = { 0x6a,0x01,0x94,0x87,0x1d,0x64,0x40,0x37,0xc6,0xe0,0x4f,0x52,0xd5,0x28,0xbd,0x47 };
    const uint8_t IV[] = { 0x79,0xf0,0xa9,0x56,0x67,0x0b,0x3d,0x53,0xe5,0xa7,0x9e,0x5b,0xfe,0x47,0x0b,0xcd };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-35", "[CFB1][MCT][128][ENCRYPT][n35]") {
    const uint8_t KEY[] = { 0x4f,0xac,0x25,0x77,0x57,0x80,0x55,0xff,0x74,0xc4,0xce,0x81,0xc7,0x07,0xaf,0xd7 };
    const uint8_t IV[] = { 0x25,0xad,0xb1,0xf0,0x4a,0xe4,0x15,0xc8,0xb2,0x24,0x81,0xd3,0x12,0x2f,0x12,0x90 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-36", "[CFB1][MCT][128][ENCRYPT][n36]") {
    const uint8_t KEY[] = { 0xe8,0x23,0x45,0x5a,0x70,0xc4,0x47,0xfc,0xf2,0x0b,0x9a,0xdd,0xae,0xb1,0x31,0x0b };
    const uint8_t IV[] = { 0xa7,0x8f,0x60,0x2d,0x27,0x44,0x12,0x03,0x86,0xcf,0x54,0x5c,0x69,0xb6,0x9e,0xdc };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-37", "[CFB1][MCT][128][ENCRYPT][n37]") {
    const uint8_t KEY[] = { 0xfb,0x6b,0xf6,0xfc,0xc3,0x8d,0xdc,0x49,0xb6,0x76,0xae,0xb6,0x1b,0x0c,0x19,0xf3 };
    const uint8_t IV[] = { 0x13,0x48,0xb3,0xa6,0xb3,0x49,0x9b,0xb5,0x44,0x7d,0x34,0x6b,0xb5,0xbd,0x28,0xf8 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-38", "[CFB1][MCT][128][ENCRYPT][n38]") {
    const uint8_t KEY[] = { 0xae,0xc7,0x1c,0xca,0x29,0xba,0x30,0x9c,0x0c,0x06,0x89,0x09,0x52,0x4f,0x62,0xb8 };
    const uint8_t IV[] = { 0x55,0xac,0xea,0x36,0xea,0x37,0xec,0xd5,0xba,0x70,0x27,0xbf,0x49,0x43,0x7b,0x4b };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-39", "[CFB1][MCT][128][ENCRYPT][n39]") {
    const uint8_t KEY[] = { 0x7e,0x5f,0x3e,0x74,0xe8,0xf8,0xfa,0x94,0xab,0x36,0xca,0xbf,0x99,0x26,0x83,0x8b };
    const uint8_t IV[] = { 0xd0,0x98,0x22,0xbe,0xc1,0x42,0xca,0x08,0xa7,0x30,0x43,0xb6,0xcb,0x69,0xe1,0x33 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-40", "[CFB1][MCT][128][ENCRYPT][n40]") {
    const uint8_t KEY[] = { 0xcb,0x75,0x11,0xab,0x56,0x42,0x7b,0xe4,0x28,0x09,0x00,0xcd,0xe9,0xf2,0xa2,0xd2 };
    const uint8_t IV[] = { 0xb5,0x2a,0x2f,0xdf,0xbe,0xba,0x81,0x70,0x83,0x3f,0xca,0x72,0x70,0xd4,0x21,0x59 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-41", "[CFB1][MCT][128][ENCRYPT][n41]") {
    const uint8_t KEY[] = { 0x9e,0x1c,0xb3,0xd2,0xf0,0x86,0x88,0x86,0x2d,0xf8,0xfe,0x7f,0xaa,0x3b,0x75,0xb8 };
    const uint8_t IV[] = { 0x55,0x69,0xa2,0x79,0xa6,0xc4,0xf3,0x62,0x05,0xf1,0xfe,0xb2,0x43,0xc9,0xd7,0x6a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-42", "[CFB1][MCT][128][ENCRYPT][n42]") {
    const uint8_t KEY[] = { 0x8b,0xc1,0x31,0x93,0x60,0xcb,0x24,0x8a,0x25,0x4c,0x38,0x27,0x0d,0x9a,0x67,0x0c };
    const uint8_t IV[] = { 0x15,0xdd,0x82,0x41,0x90,0x4d,0xac,0x0c,0x08,0xb4,0xc6,0x58,0xa7,0xa1,0x12,0xb4 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-43", "[CFB1][MCT][128][ENCRYPT][n43]") {
    const uint8_t KEY[] = { 0xa6,0x40,0x3f,0xf4,0x14,0xb7,0xe1,0x28,0x06,0xa0,0x04,0xf4,0x60,0xa5,0xc5,0xc1 };
    const uint8_t IV[] = { 0x2d,0x81,0x0e,0x67,0x74,0x7c,0xc5,0xa2,0x23,0xec,0x3c,0xd3,0x6d,0x3f,0xa2,0xcd };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-44", "[CFB1][MCT][128][ENCRYPT][n44]") {
    const uint8_t KEY[] = { 0x55,0x01,0x06,0xf7,0xda,0xa4,0xf8,0x44,0x45,0x2f,0x87,0x25,0xae,0x0c,0x15,0x11 };
    const uint8_t IV[] = { 0xf3,0x41,0x39,0x03,0xce,0x13,0x19,0x6c,0x43,0x8f,0x83,0xd1,0xce,0xa9,0xd0,0xd0 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-45", "[CFB1][MCT][128][ENCRYPT][n45]") {
    const uint8_t KEY[] = { 0x7a,0x58,0x34,0x7f,0x04,0x65,0x94,0x28,0x31,0x05,0x30,0x2e,0x71,0x37,0x46,0x51 };
    const uint8_t IV[] = { 0x2f,0x59,0x32,0x88,0xde,0xc1,0x6c,0x6c,0x74,0x2a,0xb7,0x0b,0xdf,0x3b,0x53,0x40 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-46", "[CFB1][MCT][128][ENCRYPT][n46]") {
    const uint8_t KEY[] = { 0x51,0x45,0x46,0x02,0x2f,0xc8,0xae,0x05,0xa7,0x88,0x03,0x7d,0xd4,0x49,0x2a,0x7b };
    const uint8_t IV[] = { 0x2b,0x1d,0x72,0x7d,0x2b,0xad,0x3a,0x2d,0x96,0x8d,0x33,0x53,0xa5,0x7e,0x6c,0x2a };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-47", "[CFB1][MCT][128][ENCRYPT][n47]") {
    const uint8_t KEY[] = { 0x11,0x6a,0xc4,0xb7,0x21,0xa4,0xcf,0x4c,0xa2,0x72,0xe8,0x1f,0xc6,0x4a,0x82,0x85 };
    const uint8_t IV[] = { 0x40,0x2f,0x82,0xb5,0x0e,0x6c,0x61,0x49,0x05,0xfa,0xeb,0x62,0x12,0x03,0xa8,0xfe };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-48", "[CFB1][MCT][128][ENCRYPT][n48]") {
    const uint8_t KEY[] = { 0x36,0xbf,0x6c,0x4a,0xce,0x26,0xbd,0x80,0x59,0x55,0x33,0x95,0x99,0xff,0x77,0xa3 };
    const uint8_t IV[] = { 0x27,0xd5,0xa8,0xfd,0xef,0x82,0x72,0xcc,0xfb,0x27,0xdb,0x8a,0x5f,0xb5,0xf5,0x26 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-49", "[CFB1][MCT][128][ENCRYPT][n49]") {
    const uint8_t KEY[] = { 0xe7,0x06,0x89,0xc7,0x0b,0xac,0x9c,0x30,0x29,0x2b,0xcb,0xba,0x12,0x6c,0xdd,0xbd };
    const uint8_t IV[] = { 0xd1,0xb9,0xe5,0x8d,0xc5,0x8a,0x21,0xb0,0x70,0x7e,0xf8,0x2f,0x8b,0x93,0xaa,0x1e };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-50", "[CFB1][MCT][128][ENCRYPT][n50]") {
    const uint8_t KEY[] = { 0x2e,0x0b,0x24,0xd4,0x95,0xe6,0x5a,0xd5,0x94,0x88,0xb3,0x1f,0x07,0x44,0x79,0xdc };
    const uint8_t IV[] = { 0xc9,0x0d,0xad,0x13,0x9e,0x4a,0xc6,0xe5,0xbd,0xa3,0x78,0xa5,0x15,0x28,0xa4,0x61 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-51", "[CFB1][MCT][128][ENCRYPT][n51]") {
    const uint8_t KEY[] = { 0xac,0xe8,0xa8,0x02,0xba,0x6d,0xef,0x08,0x3a,0x21,0xce,0x2d,0x9c,0xd5,0x39,0xa1 };
    const uint8_t IV[] = { 0x82,0xe3,0x8c,0xd6,0x2f,0x8b,0xb5,0xdd,0xae,0xa9,0x7d,0x32,0x9b,0x91,0x40,0x7d };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-52", "[CFB1][MCT][128][ENCRYPT][n52]") {
    const uint8_t KEY[] = { 0x9c,0xbf,0xd3,0xa6,0x67,0xe1,0x25,0x1b,0x74,0x5b,0x4c,0x3e,0xab,0x30,0x08,0xf2 };
    const uint8_t IV[] = { 0x30,0x57,0x7b,0xa4,0xdd,0x8c,0xca,0x13,0x4e,0x7a,0x82,0x13,0x37,0xe5,0x31,0x53 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-53", "[CFB1][MCT][128][ENCRYPT][n53]") {
    const uint8_t KEY[] = { 0x69,0x1b,0xdc,0x2b,0x32,0xd9,0x51,0x2f,0xf9,0xbe,0xc6,0xe4,0x2a,0xe9,0x75,0x29 };
    const uint8_t IV[] = { 0xf5,0xa4,0x0f,0x8d,0x55,0x38,0x74,0x34,0x8d,0xe5,0x8a,0xda,0x81,0xd9,0x7d,0xdb };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-54", "[CFB1][MCT][128][ENCRYPT][n54]") {
    const uint8_t KEY[] = { 0x63,0xdf,0xb7,0x26,0x57,0x46,0xec,0x99,0x38,0xce,0x25,0x70,0x77,0xc9,0x75,0x39 };
    const uint8_t IV[] = { 0x0a,0xc4,0x6b,0x0d,0x65,0x9f,0xbd,0xb6,0xc1,0x70,0xe3,0x94,0x5d,0x20,0x00,0x10 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-55", "[CFB1][MCT][128][ENCRYPT][n55]") {
    const uint8_t KEY[] = { 0xa9,0xea,0xba,0x19,0xdf,0xf7,0x1a,0x59,0x9b,0x6e,0xf0,0xda,0xea,0xcb,0xb7,0xe4 };
    const uint8_t IV[] = { 0xca,0x35,0x0d,0x3f,0x88,0xb1,0xf6,0xc0,0xa3,0xa0,0xd5,0xaa,0x9d,0x02,0xc2,0xdd };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-56", "[CFB1][MCT][128][ENCRYPT][n56]") {
    const uint8_t KEY[] = { 0x97,0xfb,0xe1,0x45,0x18,0x47,0x98,0x05,0xea,0xf5,0xd4,0xd4,0x16,0x31,0x87,0x12 };
    const uint8_t IV[] = { 0x3e,0x11,0x5b,0x5c,0xc7,0xb0,0x82,0x5c,0x71,0x9b,0x24,0x0e,0xfc,0xfa,0x30,0xf6 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-57", "[CFB1][MCT][128][ENCRYPT][n57]") {
    const uint8_t KEY[] = { 0x78,0xfb,0xce,0xb6,0x90,0xf0,0xe7,0x53,0x38,0x11,0x4d,0x5c,0x0c,0xfc,0xe7,0x7c };
    const uint8_t IV[] = { 0xef,0x00,0x2f,0xf3,0x88,0xb7,0x7f,0x56,0xd2,0xe4,0x99,0x88,0x1a,0xcd,0x60,0x6e };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-58", "[CFB1][MCT][128][ENCRYPT][n58]") {
    const uint8_t KEY[] = { 0xd3,0x78,0x0e,0x1e,0xd6,0x7c,0xc8,0xe9,0xd5,0x63,0xb2,0xdb,0x86,0x14,0x74,0x4e };
    const uint8_t IV[] = { 0xab,0x83,0xc0,0xa8,0x46,0x8c,0x2f,0xba,0xed,0x72,0xff,0x87,0x8a,0xe8,0x93,0x32 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-59", "[CFB1][MCT][128][ENCRYPT][n59]") {
    const uint8_t KEY[] = { 0x2b,0x57,0x61,0xe5,0xa9,0x70,0x88,0x04,0x3c,0x7b,0x8b,0x9f,0x5d,0xec,0xf9,0x72 };
    const uint8_t IV[] = { 0xf8,0x2f,0x6f,0xfb,0x7f,0x0c,0x40,0xed,0xe9,0x18,0x39,0x44,0xdb,0xf8,0x8d,0x3c };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-60", "[CFB1][MCT][128][ENCRYPT][n60]") {
    const uint8_t KEY[] = { 0x87,0x90,0xb7,0xd4,0x44,0x1d,0xae,0xb0,0x12,0x9b,0x2e,0x82,0xb1,0x1f,0x60,0x7c };
    const uint8_t IV[] = { 0xac,0xc7,0xd6,0x31,0xed,0x6d,0x26,0xb4,0x2e,0xe0,0xa5,0x1d,0xec,0xf3,0x99,0x0e };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-61", "[CFB1][MCT][128][ENCRYPT][n61]") {
    const uint8_t KEY[] = { 0xcf,0x22,0x0a,0xbc,0xe8,0xab,0xde,0x8e,0x6d,0x8d,0xed,0x3d,0xaf,0x12,0x93,0xca };
    const uint8_t IV[] = { 0x48,0xb2,0xbd,0x68,0xac,0xb6,0x70,0x3e,0x7f,0x16,0xc3,0xbf,0x1e,0x0d,0xf3,0xb6 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-62", "[CFB1][MCT][128][ENCRYPT][n62]") {
    const uint8_t KEY[] = { 0xdf,0x4e,0xa7,0xc8,0x69,0xa5,0xd9,0xd2,0xa4,0x88,0xd9,0x2b,0x07,0xad,0xa1,0x13 };
    const uint8_t IV[] = { 0x10,0x6c,0xad,0x74,0x81,0x0e,0x07,0x5c,0xc9,0x05,0x34,0x16,0xa8,0xbf,0x32,0xd9 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-63", "[CFB1][MCT][128][ENCRYPT][n63]") {
    const uint8_t KEY[] = { 0xb7,0x82,0x57,0xaa,0xbd,0x67,0x54,0xcc,0xb6,0x2f,0x22,0x3a,0xaa,0x4e,0x5a,0xef };
    const uint8_t IV[] = { 0x68,0xcc,0xf0,0x62,0xd4,0xc2,0x8d,0x1e,0x12,0xa7,0xfb,0x11,0xad,0xe3,0xfb,0xfc };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-64", "[CFB1][MCT][128][ENCRYPT][n64]") {
    const uint8_t KEY[] = { 0x51,0x9e,0x10,0xb9,0x92,0x65,0x41,0xe8,0xd3,0xb2,0x5d,0x44,0x97,0x81,0x18,0x8a };
    const uint8_t IV[] = { 0xe6,0x1c,0x47,0x13,0x2f,0x02,0x15,0x24,0x65,0x9d,0x7f,0x7e,0x3d,0xcf,0x42,0x65 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-65", "[CFB1][MCT][128][ENCRYPT][n65]") {
    const uint8_t KEY[] = { 0x53,0x7b,0x59,0xfa,0x91,0x3f,0x89,0xa5,0xd8,0x50,0xd7,0x23,0xc7,0x05,0xd5,0x7c };
    const uint8_t IV[] = { 0x02,0xe5,0x49,0x43,0x03,0x5a,0xc8,0x4d,0x0b,0xe2,0x8a,0x67,0x50,0x84,0xcd,0xf6 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-66", "[CFB1][MCT][128][ENCRYPT][n66]") {
    const uint8_t KEY[] = { 0x24,0xd4,0x47,0x9e,0x11,0xc0,0x27,0xd0,0x23,0xd0,0x80,0xc1,0x16,0x86,0x71,0xf6 };
    const uint8_t IV[] = { 0x77,0xaf,0x1e,0x64,0x80,0xff,0xae,0x75,0xfb,0x80,0x57,0xe2,0xd1,0x83,0xa4,0x8a };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-67", "[CFB1][MCT][128][ENCRYPT][n67]") {
    const uint8_t KEY[] = { 0x69,0x77,0x50,0x6a,0x51,0x59,0xc5,0xbc,0x79,0x5e,0x81,0x2b,0xb7,0xcd,0xf8,0x74 };
    const uint8_t IV[] = { 0x4d,0xa3,0x17,0xf4,0x40,0x99,0xe2,0x6c,0x5a,0x8e,0x01,0xea,0xa1,0x4b,0x89,0x82 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-68", "[CFB1][MCT][128][ENCRYPT][n68]") {
    const uint8_t KEY[] = { 0xfe,0xd8,0xb3,0xda,0x39,0xd3,0x47,0xbb,0xa6,0x2c,0x6b,0x6b,0xb4,0x06,0x85,0xd7 };
    const uint8_t IV[] = { 0x97,0xaf,0xe3,0xb0,0x68,0x8a,0x82,0x07,0xdf,0x72,0xea,0x40,0x03,0xcb,0x7d,0xa3 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-69", "[CFB1][MCT][128][ENCRYPT][n69]") {
    const uint8_t KEY[] = { 0xae,0x60,0x6b,0x89,0x1c,0x47,0x03,0x51,0x45,0xea,0xc6,0x1e,0xd1,0xe3,0x06,0x26 };
    const uint8_t IV[] = { 0x50,0xb8,0xd8,0x53,0x25,0x94,0x44,0xea,0xe3,0xc6,0xad,0x75,0x65,0xe5,0x83,0xf1 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-70", "[CFB1][MCT][128][ENCRYPT][n70]") {
    const uint8_t KEY[] = { 0x89,0x1a,0x8f,0xf1,0x4b,0x4e,0x07,0x54,0x0a,0xf1,0x4b,0x42,0x57,0xfb,0x63,0x56 };
    const uint8_t IV[] = { 0x27,0x7a,0xe4,0x78,0x57,0x09,0x04,0x05,0x4f,0x1b,0x8d,0x5c,0x86,0x18,0x65,0x70 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-71", "[CFB1][MCT][128][ENCRYPT][n71]") {
    const uint8_t KEY[] = { 0xeb,0xa7,0x56,0x41,0xb6,0xe2,0x17,0x50,0xea,0xc9,0xbf,0xe8,0x2d,0x70,0x16,0x67 };
    const uint8_t IV[] = { 0x62,0xbd,0xd9,0xb0,0xfd,0xac,0x10,0x04,0xe0,0x38,0xf4,0xaa,0x7a,0x8b,0x75,0x31 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-72", "[CFB1][MCT][128][ENCRYPT][n72]") {
    const uint8_t KEY[] = { 0x8b,0xdb,0x65,0x5f,0xbf,0x13,0xeb,0xe0,0xb3,0x80,0x96,0x03,0x52,0x0f,0x98,0x3c };
    const uint8_t IV[] = { 0x60,0x7c,0x33,0x1e,0x09,0xf1,0xfc,0xb0,0x59,0x49,0x29,0xeb,0x7f,0x7f,0x8e,0x5b };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-73", "[CFB1][MCT][128][ENCRYPT][n73]") {
    const uint8_t KEY[] = { 0x75,0x83,0xf2,0x38,0xf8,0x7a,0x3e,0x29,0x45,0x8b,0x7b,0x13,0x6e,0xad,0xaa,0x6a };
    const uint8_t IV[] = { 0xfe,0x58,0x97,0x67,0x47,0x69,0xd5,0xc9,0xf6,0x0b,0xed,0x10,0x3c,0xa2,0x32,0x56 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-74", "[CFB1][MCT][128][ENCRYPT][n74]") {
    const uint8_t KEY[] = { 0x0f,0x01,0xc8,0x70,0x8c,0x29,0x66,0x7a,0xa6,0xa7,0x7f,0xe9,0x69,0x43,0xd2,0x10 };
    const uint8_t IV[] = { 0x7a,0x82,0x3a,0x48,0x74,0x53,0x58,0x53,0xe3,0x2c,0x04,0xfa,0x07,0xee,0x78,0x7a };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-75", "[CFB1][MCT][128][ENCRYPT][n75]") {
    const uint8_t KEY[] = { 0xc9,0xec,0xae,0xe2,0x13,0x20,0x70,0x80,0xb2,0x3d,0xd3,0x75,0x77,0x8f,0xf5,0xd2 };
    const uint8_t IV[] = { 0xc6,0xed,0x66,0x92,0x9f,0x09,0x16,0xfa,0x14,0x9a,0xac,0x9c,0x1e,0xcc,0x27,0xc2 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-76", "[CFB1][MCT][128][ENCRYPT][n76]") {
    const uint8_t KEY[] = { 0xb6,0x05,0x45,0x91,0x17,0xb2,0x6f,0xc8,0x5d,0xbd,0x33,0xff,0xca,0x14,0x9e,0x63 };
    const uint8_t IV[] = { 0x7f,0xe9,0xeb,0x73,0x04,0x92,0x1f,0x48,0xef,0x80,0xe0,0x8a,0xbd,0x9b,0x6b,0xb1 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-77", "[CFB1][MCT][128][ENCRYPT][n77]") {
    const uint8_t KEY[] = { 0xf8,0x3a,0x92,0x76,0xa4,0xb7,0x4f,0x22,0x9c,0x26,0x4f,0x87,0x30,0x13,0x59,0xb5 };
    const uint8_t IV[] = { 0x4e,0x3f,0xd7,0xe7,0xb3,0x05,0x20,0xea,0xc1,0x9b,0x7c,0x78,0xfa,0x07,0xc7,0xd6 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-78", "[CFB1][MCT][128][ENCRYPT][n78]") {
    const uint8_t KEY[] = { 0x1e,0x99,0x93,0x06,0x66,0x76,0x4d,0x79,0xcf,0x5d,0x8a,0x5c,0xac,0xb3,0x67,0xc9 };
    const uint8_t IV[] = { 0xe6,0xa3,0x01,0x70,0xc2,0xc1,0x02,0x5b,0x53,0x7b,0xc5,0xdb,0x9c,0xa0,0x3e,0x7c };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-79", "[CFB1][MCT][128][ENCRYPT][n79]") {
    const uint8_t KEY[] = { 0xa8,0x46,0xfc,0xfd,0x69,0xe0,0x03,0xe9,0x6e,0xd3,0xf6,0xe0,0x9a,0x77,0xc2,0x35 };
    const uint8_t IV[] = { 0xb6,0xdf,0x6f,0xfb,0x0f,0x96,0x4e,0x90,0xa1,0x8e,0x7c,0xbc,0x36,0xc4,0xa5,0xfc };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-80", "[CFB1][MCT][128][ENCRYPT][n80]") {
    const uint8_t KEY[] = { 0x2e,0xb0,0x9f,0x71,0x56,0x41,0x25,0xaa,0xf1,0xcf,0x42,0x50,0x16,0x05,0x14,0x60 };
    const uint8_t IV[] = { 0x86,0xf6,0x63,0x8c,0x3f,0xa1,0x26,0x43,0x9f,0x1c,0xb4,0xb0,0x8c,0x72,0xd6,0x55 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-81", "[CFB1][MCT][128][ENCRYPT][n81]") {
    const uint8_t KEY[] = { 0x71,0x99,0x2f,0x0a,0x31,0xd8,0x88,0xd3,0xc9,0xaf,0x77,0xde,0xee,0xb1,0x71,0x30 };
    const uint8_t IV[] = { 0x5f,0x29,0xb0,0x7b,0x67,0x99,0xad,0x79,0x38,0x60,0x35,0x8e,0xf8,0xb4,0x65,0x50 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-82", "[CFB1][MCT][128][ENCRYPT][n82]") {
    const uint8_t KEY[] = { 0xd9,0x29,0x75,0xde,0x24,0x05,0xbb,0xb9,0x4b,0xe1,0x7c,0x39,0x74,0xac,0xef,0xfd };
    const uint8_t IV[] = { 0xa8,0xb0,0x5a,0xd4,0x15,0xdd,0x33,0x6a,0x82,0x4e,0x0b,0xe7,0x9a,0x1d,0x9e,0xcd };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-83", "[CFB1][MCT][128][ENCRYPT][n83]") {
    const uint8_t KEY[] = { 0x4e,0x44,0x65,0xa0,0x49,0x4d,0x98,0x6f,0x68,0x2c,0x93,0xc6,0x02,0x02,0x0d,0x9a };
    const uint8_t IV[] = { 0x97,0x6d,0x10,0x7e,0x6d,0x48,0x23,0xd6,0x23,0xcd,0xef,0xff,0x76,0xae,0xe2,0x67 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-84", "[CFB1][MCT][128][ENCRYPT][n84]") {
    const uint8_t KEY[] = { 0x77,0x8e,0xe8,0xaf,0x09,0xa0,0x14,0x22,0x41,0xd6,0x80,0xcc,0x11,0xf5,0x25,0x59 };
    const uint8_t IV[] = { 0x39,0xca,0x8d,0x0f,0x40,0xed,0x8c,0x4d,0x29,0xfa,0x13,0x0a,0x13,0xf7,0x28,0xc3 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-85", "[CFB1][MCT][128][ENCRYPT][n85]") {
    const uint8_t KEY[] = { 0x15,0x4c,0x65,0x3a,0xb7,0xf1,0x5a,0x32,0x51,0xaf,0x49,0xfb,0xa5,0x62,0xb8,0xb0 };
    const uint8_t IV[] = { 0x62,0xc2,0x8d,0x95,0xbe,0x51,0x4e,0x10,0x10,0x79,0xc9,0x37,0xb4,0x97,0x9d,0xe9 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-86", "[CFB1][MCT][128][ENCRYPT][n86]") {
    const uint8_t KEY[] = { 0xb9,0x9a,0x68,0x20,0x27,0x7c,0x5e,0x29,0x55,0x50,0x4f,0x6c,0xa1,0x1e,0xab,0xcf };
    const uint8_t IV[] = { 0xac,0xd6,0x0d,0x1a,0x90,0x8d,0x04,0x1b,0x04,0xff,0x06,0x97,0x04,0x7c,0x13,0x7f };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-87", "[CFB1][MCT][128][ENCRYPT][n87]") {
    const uint8_t KEY[] = { 0xcd,0x94,0x28,0x0b,0x5d,0xf9,0xd6,0xe6,0x80,0x88,0x61,0x58,0x56,0xef,0x12,0x24 };
    const uint8_t IV[] = { 0x74,0x0e,0x40,0x2b,0x7a,0x85,0x88,0xcf,0xd5,0xd8,0x2e,0x34,0xf7,0xf1,0xb9,0xeb };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-88", "[CFB1][MCT][128][ENCRYPT][n88]") {
    const uint8_t KEY[] = { 0x61,0x01,0xb1,0xb4,0x26,0x03,0xd3,0x96,0xdb,0x90,0xe5,0x99,0x9e,0x2b,0x8b,0x66 };
    const uint8_t IV[] = { 0xac,0x95,0x99,0xbf,0x7b,0xfa,0x05,0x70,0x5b,0x18,0x84,0xc1,0xc8,0xc4,0x99,0x42 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-89", "[CFB1][MCT][128][ENCRYPT][n89]") {
    const uint8_t KEY[] = { 0xe2,0x23,0x20,0x00,0x11,0xb6,0x77,0xb5,0x4f,0xac,0x68,0x07,0xf5,0x11,0x0b,0xd6 };
    const uint8_t IV[] = { 0x83,0x22,0x91,0xb4,0x37,0xb5,0xa4,0x23,0x94,0x3c,0x8d,0x9e,0x6b,0x3a,0x80,0xb0 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-90", "[CFB1][MCT][128][ENCRYPT][n90]") {
    const uint8_t KEY[] = { 0xd3,0xcd,0x50,0xa1,0x5f,0x6a,0x87,0x84,0x19,0x7e,0xcb,0xcb,0x0a,0x58,0x9a,0x72 };
    const uint8_t IV[] = { 0x31,0xee,0x70,0xa1,0x4e,0xdc,0xf0,0x31,0x56,0xd2,0xa3,0xcc,0xff,0x49,0x91,0xa4 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-91", "[CFB1][MCT][128][ENCRYPT][n91]") {
    const uint8_t KEY[] = { 0x86,0x70,0x2f,0x19,0xfd,0x5a,0x0c,0x6c,0xa8,0xe8,0xa0,0x06,0x21,0xc0,0xb6,0x81 };
    const uint8_t IV[] = { 0x55,0xbd,0x7f,0xb8,0xa2,0x30,0x8b,0xe8,0xb1,0x96,0x6b,0xcd,0x2b,0x98,0x2c,0xf3 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-92", "[CFB1][MCT][128][ENCRYPT][n92]") {
    const uint8_t KEY[] = { 0x5d,0xd7,0x0f,0xfb,0xe0,0x7c,0x0a,0xd0,0xc7,0x18,0xb2,0x4d,0xc1,0x28,0x9d,0xd2 };
    const uint8_t IV[] = { 0xdb,0xa7,0x20,0xe2,0x1d,0x26,0x06,0xbc,0x6f,0xf0,0x12,0x4b,0xe0,0xe8,0x2b,0x53 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-93", "[CFB1][MCT][128][ENCRYPT][n93]") {
    const uint8_t KEY[] = { 0xed,0xc4,0x00,0x69,0x0f,0x3a,0xcf,0xba,0x97,0x0e,0x89,0x47,0xdd,0x03,0x21,0x0a };
    const uint8_t IV[] = { 0xb0,0x13,0x0f,0x92,0xef,0x46,0xc5,0x6a,0x50,0x16,0x3b,0x0a,0x1c,0x2b,0xbc,0xd8 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-94", "[CFB1][MCT][128][ENCRYPT][n94]") {
    const uint8_t KEY[] = { 0xfb,0x52,0xe5,0x37,0x89,0x71,0x9b,0xb8,0x7f,0xac,0xd3,0x29,0xbe,0x50,0x9d,0x2c };
    const uint8_t IV[] = { 0x16,0x96,0xe5,0x5e,0x86,0x4b,0x54,0x02,0xe8,0xa2,0x5a,0x6e,0x63,0x53,0xbc,0x26 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-95", "[CFB1][MCT][128][ENCRYPT][n95]") {
    const uint8_t KEY[] = { 0xcd,0x6f,0x63,0x31,0xd4,0xbe,0xb4,0x99,0xf2,0x2d,0x28,0x79,0xb4,0x98,0xab,0xe3 };
    const uint8_t IV[] = { 0x36,0x3d,0x86,0x06,0x5d,0xcf,0x2f,0x21,0x8d,0x81,0xfb,0x50,0x0a,0xc8,0x36,0xcf };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-96", "[CFB1][MCT][128][ENCRYPT][n96]") {
    const uint8_t KEY[] = { 0x2c,0x51,0x7b,0xf6,0x58,0x1f,0x07,0x7e,0xe3,0xe8,0x71,0x26,0x4d,0xb2,0x7e,0x6c };
    const uint8_t IV[] = { 0xe1,0x3e,0x18,0xc7,0x8c,0xa1,0xb3,0xe7,0x11,0xc5,0x59,0x5f,0xf9,0x2a,0xd5,0x8f };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-97", "[CFB1][MCT][128][ENCRYPT][n97]") {
    const uint8_t KEY[] = { 0xf5,0x9d,0x87,0xe8,0xfa,0x31,0x43,0x95,0xab,0x59,0xcc,0x19,0xd3,0xd0,0xc0,0x01 };
    const uint8_t IV[] = { 0xd9,0xcc,0xfc,0x1e,0xa2,0x2e,0x44,0xeb,0x48,0xb1,0xbd,0x3f,0x9e,0x62,0xbe,0x6d };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-98", "[CFB1][MCT][128][ENCRYPT][n98]") {
    const uint8_t KEY[] = { 0xa1,0x2d,0xd1,0xc3,0xa1,0x3a,0x20,0x4d,0xae,0xaf,0x5a,0x9d,0xe0,0x0e,0xb1,0x88 };
    const uint8_t IV[] = { 0x54,0xb0,0x56,0x2b,0x5b,0x0b,0x63,0xd8,0x05,0xf6,0x96,0x84,0x33,0xde,0x71,0x89 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-ENCRYPT-99", "[CFB1][MCT][128][ENCRYPT][n99]") {
    const uint8_t KEY[] = { 0x81,0xdb,0xb3,0x84,0x38,0x50,0x1c,0x0c,0x10,0x08,0x0a,0x5f,0x7f,0x37,0xbd,0x92 };
    const uint8_t IV[] = { 0x20,0xf6,0x62,0x47,0x99,0x6a,0x3c,0x41,0xbe,0xa7,0x50,0xc2,0x9f,0x39,0x0c,0x1a };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb1(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-0", "[CFB1][MCT][128][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0xc4,0x12,0x41,0x5e,0x40,0x5a,0x77,0xd0,0xe9,0xa3,0x10,0xed,0x1c,0xa8,0x6a,0xe6 };
    const uint8_t IV[] = { 0xc0,0xdf,0x93,0x71,0x53,0xeb,0x5d,0x8a,0xe4,0xe3,0xb2,0x0f,0x0b,0x8e,0x90,0x16 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-1", "[CFB1][MCT][128][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0x8d,0xe8,0x7e,0x23,0xad,0xa2,0x73,0xf3,0x4d,0x27,0x86,0x76,0x7e,0x8c,0xc1,0x11 };
    const uint8_t IV[] = { 0x49,0xfa,0x3f,0x7d,0xed,0xf8,0x04,0x23,0xa4,0x84,0x96,0x9b,0x62,0x24,0xab,0xf7 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-2", "[CFB1][MCT][128][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0x77,0x06,0xff,0xf8,0x3f,0x6a,0xb0,0xb8,0x91,0x7a,0x74,0xd9,0x69,0x98,0x33,0x30 };
    const uint8_t IV[] = { 0xfa,0xee,0x81,0xdb,0x92,0xc8,0xc3,0x4b,0xdc,0x5d,0xf2,0xaf,0x17,0x14,0xf2,0x21 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-3", "[CFB1][MCT][128][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0x85,0x46,0xd1,0xcc,0x94,0xe8,0xb3,0xa4,0xa0,0xc8,0xd8,0x94,0x67,0x20,0x49,0xe5 };
    const uint8_t IV[] = { 0xf2,0x40,0x2e,0x34,0xab,0x82,0x03,0x1c,0x31,0xb2,0xac,0x4d,0x0e,0xb8,0x7a,0xd5 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-4", "[CFB1][MCT][128][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0x5e,0xa8,0xf4,0xe2,0xfc,0xf5,0x74,0x54,0x2d,0x11,0x57,0x39,0x0a,0x2f,0x7c,0x48 };
    const uint8_t IV[] = { 0xdb,0xee,0x25,0x2e,0x68,0x1d,0xc7,0xf0,0x8d,0xd9,0x8f,0xad,0x6d,0x0f,0x35,0xad };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-5", "[CFB1][MCT][128][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0x86,0x33,0xfd,0x44,0x44,0xf4,0x0b,0xbd,0x30,0xc5,0xc7,0x57,0xa8,0xc5,0xa3,0x4a };
    const uint8_t IV[] = { 0xd8,0x9b,0x09,0xa6,0xb8,0x01,0x7f,0xe9,0x1d,0xd4,0x90,0x6e,0xa2,0xea,0xdf,0x02 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-6", "[CFB1][MCT][128][DECRYPT][n6]") {
    const uint8_t KEY[] = { 0x23,0xa6,0x38,0xea,0x22,0x2f,0x56,0x14,0xc5,0x14,0xfb,0x04,0xce,0xb9,0x3c,0x86 };
    const uint8_t IV[] = { 0xa5,0x95,0xc5,0xae,0x66,0xdb,0x5d,0xa9,0xf5,0xd1,0x3c,0x53,0x66,0x7c,0x9f,0xcc };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-7", "[CFB1][MCT][128][DECRYPT][n7]") {
    const uint8_t KEY[] = { 0xb7,0x79,0x25,0x33,0x71,0xab,0xc0,0xc6,0x85,0x6d,0x69,0xbe,0x5d,0x2b,0x7d,0x77 };
    const uint8_t IV[] = { 0x94,0xdf,0x1d,0xd9,0x53,0x84,0x96,0xd2,0x40,0x79,0x92,0xba,0x93,0x92,0x41,0xf1 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-8", "[CFB1][MCT][128][DECRYPT][n8]") {
    const uint8_t KEY[] = { 0xb9,0x23,0x5e,0xd2,0x64,0x80,0xf5,0xe3,0x3c,0xa4,0x81,0xf7,0xa0,0x3a,0x12,0xb4 };
    const uint8_t IV[] = { 0x0e,0x5a,0x7b,0xe1,0x15,0x2b,0x35,0x25,0xb9,0xc9,0xe8,0x49,0xfd,0x11,0x6f,0xc3 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-9", "[CFB1][MCT][128][DECRYPT][n9]") {
    const uint8_t KEY[] = { 0xa9,0xc2,0xa8,0xe4,0xdc,0x86,0x7f,0xb6,0xc8,0x7c,0x8f,0x30,0x23,0x53,0xfa,0xdd };
    const uint8_t IV[] = { 0x10,0xe1,0xf6,0x36,0xb8,0x06,0x8a,0x55,0xf4,0xd8,0x0e,0xc7,0x83,0x69,0xe8,0x69 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-10", "[CFB1][MCT][128][DECRYPT][n10]") {
    const uint8_t KEY[] = { 0x99,0x72,0x08,0xaf,0x18,0xf3,0x1e,0x6b,0x2f,0x6f,0x2a,0x09,0x35,0xc3,0xcd,0xa8 };
    const uint8_t IV[] = { 0x30,0xb0,0xa0,0x4b,0xc4,0x75,0x61,0xdd,0xe7,0x13,0xa5,0x39,0x16,0x90,0x37,0x75 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-11", "[CFB1][MCT][128][DECRYPT][n11]") {
    const uint8_t KEY[] = { 0xaa,0xb8,0xfd,0xfc,0x3d,0x85,0x14,0x5a,0x09,0x2a,0x70,0x91,0x36,0xdb,0xeb,0x20 };
    const uint8_t IV[] = { 0x33,0xca,0xf5,0x53,0x25,0x76,0x0a,0x31,0x26,0x45,0x5a,0x98,0x03,0x18,0x26,0x88 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-12", "[CFB1][MCT][128][DECRYPT][n12]") {
    const uint8_t KEY[] = { 0x38,0xb1,0x1a,0x40,0x5c,0xe8,0x78,0x6a,0x68,0x2f,0x01,0x86,0x12,0x84,0x5c,0x8b };
    const uint8_t IV[] = { 0x92,0x09,0xe7,0xbc,0x61,0x6d,0x6c,0x30,0x61,0x05,0x71,0x17,0x24,0x5f,0xb7,0xab };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-13", "[CFB1][MCT][128][DECRYPT][n13]") {
    const uint8_t KEY[] = { 0x14,0x7e,0xda,0x40,0x7b,0x7e,0xd4,0xa9,0x1f,0x48,0x9c,0xb7,0xf6,0x3d,0xaf,0xda };
    const uint8_t IV[] = { 0x2c,0xcf,0xc0,0x00,0x27,0x96,0xac,0xc3,0x77,0x67,0x9d,0x31,0xe4,0xb9,0xf3,0x51 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-14", "[CFB1][MCT][128][DECRYPT][n14]") {
    const uint8_t KEY[] = { 0x16,0x7e,0x65,0x84,0x25,0xc9,0xae,0x60,0xdf,0x3d,0x14,0xba,0x73,0xde,0x14,0x59 };
    const uint8_t IV[] = { 0x02,0x00,0xbf,0xc4,0x5e,0xb7,0x7a,0xc9,0xc0,0x75,0x88,0x0d,0x85,0xe3,0xbb,0x83 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-15", "[CFB1][MCT][128][DECRYPT][n15]") {
    const uint8_t KEY[] = { 0xc3,0x45,0x10,0x36,0xe9,0xa8,0xbb,0x7c,0x1d,0x53,0x48,0x31,0xd4,0xad,0x63,0xdd };
    const uint8_t IV[] = { 0xd5,0x3b,0x75,0xb2,0xcc,0x61,0x15,0x1c,0xc2,0x6e,0x5c,0x8b,0xa7,0x73,0x77,0x84 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-16", "[CFB1][MCT][128][DECRYPT][n16]") {
    const uint8_t KEY[] = { 0x0e,0x15,0x94,0x67,0xda,0x7f,0x0e,0x1f,0x49,0xb1,0xf9,0x0d,0xe2,0x4f,0x32,0xdc };
    const uint8_t IV[] = { 0xcd,0x50,0x84,0x51,0x33,0xd7,0xb5,0x63,0x54,0xe2,0xb1,0x3c,0x36,0xe2,0x51,0x01 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-17", "[CFB1][MCT][128][DECRYPT][n17]") {
    const uint8_t KEY[] = { 0xa9,0xac,0x2f,0x58,0x6e,0x74,0x04,0xd1,0x7d,0xba,0xd0,0xe1,0xba,0x16,0x17,0x2b };
    const uint8_t IV[] = { 0xa7,0xb9,0xbb,0x3f,0xb4,0x0b,0x0a,0xce,0x34,0x0b,0x29,0xec,0x58,0x59,0x25,0xf7 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-18", "[CFB1][MCT][128][DECRYPT][n18]") {
    const uint8_t KEY[] = { 0xab,0x29,0x56,0x44,0x05,0x35,0x38,0x90,0xab,0x45,0x0e,0x01,0xcd,0x92,0xb8,0xf6 };
    const uint8_t IV[] = { 0x02,0x85,0x79,0x1c,0x6b,0x41,0x3c,0x41,0xd6,0xff,0xde,0xe0,0x77,0x84,0xaf,0xdd };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-19", "[CFB1][MCT][128][DECRYPT][n19]") {
    const uint8_t KEY[] = { 0x53,0x05,0x25,0x9e,0xd4,0xa3,0x71,0x63,0xae,0x33,0x13,0x81,0xd1,0x2c,0xc2,0xd1 };
    const uint8_t IV[] = { 0xf8,0x2c,0x73,0xda,0xd1,0x96,0x49,0xf3,0x05,0x76,0x1d,0x80,0x1c,0xbe,0x7a,0x27 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-20", "[CFB1][MCT][128][DECRYPT][n20]") {
    const uint8_t KEY[] = { 0x80,0xcc,0xb8,0x2e,0xb7,0x64,0x67,0xe3,0x4d,0x77,0x2e,0xa3,0x15,0xb8,0x48,0x80 };
    const uint8_t IV[] = { 0xd3,0xc9,0x9d,0xb0,0x63,0xc7,0x16,0x80,0xe3,0x44,0x3d,0x22,0xc4,0x94,0x8a,0x51 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-21", "[CFB1][MCT][128][DECRYPT][n21]") {
    const uint8_t KEY[] = { 0xb9,0x79,0xe0,0xe4,0x40,0xa1,0x81,0xbf,0x1f,0x62,0xe5,0xbe,0xb3,0x40,0x28,0x8c };
    const uint8_t IV[] = { 0x39,0xb5,0x58,0xca,0xf7,0xc5,0xe6,0x5c,0x52,0x15,0xcb,0x1d,0xa6,0xf8,0x60,0x0c };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-22", "[CFB1][MCT][128][DECRYPT][n22]") {
    const uint8_t KEY[] = { 0x6e,0x4e,0x89,0xc3,0x79,0xbe,0x52,0x3f,0x10,0x96,0x77,0xfa,0x56,0xbb,0xe6,0x7f };
    const uint8_t IV[] = { 0xd7,0x37,0x69,0x27,0x39,0x1f,0xd3,0x80,0x0f,0xf4,0x92,0x44,0xe5,0xfb,0xce,0xf3 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-23", "[CFB1][MCT][128][DECRYPT][n23]") {
    const uint8_t KEY[] = { 0xe8,0xde,0xc6,0x34,0xab,0x7f,0xa5,0x6d,0xdd,0xae,0x6e,0x78,0x78,0xc5,0x82,0x27 };
    const uint8_t IV[] = { 0x86,0x90,0x4f,0xf7,0xd2,0xc1,0xf7,0x52,0xcd,0x38,0x19,0x82,0x2e,0x7e,0x64,0x58 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-24", "[CFB1][MCT][128][DECRYPT][n24]") {
    const uint8_t KEY[] = { 0xc9,0x3d,0x97,0x77,0x4b,0x3b,0x09,0x45,0x3d,0x15,0x32,0x0e,0xaa,0x54,0xa8,0x16 };
    const uint8_t IV[] = { 0x21,0xe3,0x51,0x43,0xe0,0x44,0xac,0x28,0xe0,0xbb,0x5c,0x76,0xd2,0x91,0x2a,0x31 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-25", "[CFB1][MCT][128][DECRYPT][n25]") {
    const uint8_t KEY[] = { 0xb5,0x34,0xa2,0x4d,0x82,0xf2,0xcd,0x8a,0xfb,0xac,0x9c,0x69,0xe3,0x48,0xb6,0x93 };
    const uint8_t IV[] = { 0x7c,0x09,0x35,0x3a,0xc9,0xc9,0xc4,0xcf,0xc6,0xb9,0xae,0x67,0x49,0x1c,0x1e,0x85 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-26", "[CFB1][MCT][128][DECRYPT][n26]") {
    const uint8_t KEY[] = { 0x4e,0x31,0xa4,0x67,0x70,0x72,0x4a,0xf0,0x3e,0xf2,0x27,0x44,0x4f,0xe1,0x61,0xda };
    const uint8_t IV[] = { 0xfb,0x05,0x06,0x2a,0xf2,0x80,0x87,0x7a,0xc5,0x5e,0xbb,0x2d,0xac,0xa9,0xd7,0x49 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-27", "[CFB1][MCT][128][DECRYPT][n27]") {
    const uint8_t KEY[] = { 0xd3,0x62,0x73,0x8a,0x44,0x40,0x26,0xcf,0xb1,0x24,0x76,0x22,0x82,0xf4,0x20,0xee };
    const uint8_t IV[] = { 0x9d,0x53,0xd7,0xed,0x34,0x32,0x6c,0x3f,0x8f,0xd6,0x51,0x66,0xcd,0x15,0x41,0x34 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-28", "[CFB1][MCT][128][DECRYPT][n28]") {
    const uint8_t KEY[] = { 0xee,0xe5,0x2d,0xe3,0x1e,0xd8,0xe8,0x97,0xc3,0xf0,0x6b,0x32,0x16,0x83,0xef,0xf6 };
    const uint8_t IV[] = { 0x3d,0x87,0x5e,0x69,0x5a,0x98,0xce,0x58,0x72,0xd4,0x1d,0x10,0x94,0x77,0xcf,0x18 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-29", "[CFB1][MCT][128][DECRYPT][n29]") {
    const uint8_t KEY[] = { 0xc7,0x9b,0x94,0x49,0x8c,0xb1,0xd1,0xf8,0x34,0xf8,0x64,0xa8,0x60,0x73,0x13,0x04 };
    const uint8_t IV[] = { 0x29,0x7e,0xb9,0xaa,0x92,0x69,0x39,0x6f,0xf7,0x08,0x0f,0x9a,0x76,0xf0,0xfc,0xf2 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-30", "[CFB1][MCT][128][DECRYPT][n30]") {
    const uint8_t KEY[] = { 0xef,0x9e,0x3c,0x4e,0x4f,0x2b,0xc7,0x11,0xb6,0x0d,0x41,0x3a,0xd7,0x9d,0xa5,0x7c };
    const uint8_t IV[] = { 0x28,0x05,0xa8,0x07,0xc3,0x9a,0x16,0xe9,0x82,0xf5,0x25,0x92,0xb7,0xee,0xb6,0x78 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-31", "[CFB1][MCT][128][DECRYPT][n31]") {
    const uint8_t KEY[] = { 0x87,0x87,0x3d,0x52,0x6b,0x8c,0x59,0x5c,0x01,0x7f,0x4d,0x25,0x12,0x76,0x47,0xf8 };
    const uint8_t IV[] = { 0x68,0x19,0x01,0x1c,0x24,0xa7,0x9e,0x4d,0xb7,0x72,0x0c,0x1f,0xc5,0xeb,0xe2,0x84 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-32", "[CFB1][MCT][128][DECRYPT][n32]") {
    const uint8_t KEY[] = { 0xb7,0x8a,0xdc,0x8f,0x88,0x10,0xb5,0xa9,0x73,0x22,0xa7,0x49,0x36,0xd8,0x05,0x40 };
    const uint8_t IV[] = { 0x30,0x0d,0xe1,0xdd,0xe3,0x9c,0xec,0xf5,0x72,0x5d,0xea,0x6c,0x24,0xae,0x42,0xb8 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-33", "[CFB1][MCT][128][DECRYPT][n33]") {
    const uint8_t KEY[] = { 0x87,0xf0,0x89,0x11,0x7e,0xbe,0x60,0x68,0x5f,0x20,0x00,0x6a,0x22,0xed,0x6a,0xed };
    const uint8_t IV[] = { 0x30,0x7a,0x55,0x9e,0xf6,0xae,0xd5,0xc1,0x2c,0x02,0xa7,0x23,0x14,0x35,0x6f,0xad };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-34", "[CFB1][MCT][128][DECRYPT][n34]") {
    const uint8_t KEY[] = { 0xa4,0xa6,0xf6,0xed,0xd7,0x81,0x79,0x97,0x22,0x28,0x7f,0x92,0x65,0x8d,0x65,0xcc };
    const uint8_t IV[] = { 0x23,0x56,0x7f,0xfc,0xa9,0x3f,0x19,0xff,0x7d,0x08,0x7f,0xf8,0x47,0x60,0x0f,0x21 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-35", "[CFB1][MCT][128][DECRYPT][n35]") {
    const uint8_t KEY[] = { 0xdb,0xe8,0x2b,0x31,0x4b,0x2e,0xf1,0xb3,0xa3,0xfc,0x42,0xc0,0x19,0xed,0x9c,0x95 };
    const uint8_t IV[] = { 0x7f,0x4e,0xdd,0xdc,0x9c,0xaf,0x88,0x24,0x81,0xd4,0x3d,0x52,0x7c,0x60,0xf9,0x59 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-36", "[CFB1][MCT][128][DECRYPT][n36]") {
    const uint8_t KEY[] = { 0x2a,0x63,0x0f,0x54,0x23,0xc4,0x66,0x28,0xb2,0x83,0x9e,0xde,0xe4,0xa7,0xe4,0xb0 };
    const uint8_t IV[] = { 0xf1,0x8b,0x24,0x65,0x68,0xea,0x97,0x9b,0x11,0x7f,0xdc,0x1e,0xfd,0x4a,0x78,0x25 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-37", "[CFB1][MCT][128][DECRYPT][n37]") {
    const uint8_t KEY[] = { 0x07,0xa1,0xb3,0x22,0xe0,0x35,0x4e,0x56,0x1b,0x16,0x1a,0xd0,0xe7,0x17,0x1c,0x03 };
    const uint8_t IV[] = { 0x2d,0xc2,0xbc,0x76,0xc3,0xf1,0x28,0x7e,0xa9,0x95,0x84,0x0e,0x03,0xb0,0xf8,0xb3 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-38", "[CFB1][MCT][128][DECRYPT][n38]") {
    const uint8_t KEY[] = { 0x54,0x3a,0xa6,0x15,0xda,0x53,0xc2,0x44,0xf3,0x37,0xcd,0x5b,0x27,0x6f,0x77,0x9a };
    const uint8_t IV[] = { 0x53,0x9b,0x15,0x37,0x3a,0x66,0x8c,0x12,0xe8,0x21,0xd7,0x8b,0xc0,0x78,0x6b,0x99 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-39", "[CFB1][MCT][128][DECRYPT][n39]") {
    const uint8_t KEY[] = { 0x19,0x3f,0x1b,0xce,0x83,0x40,0x0f,0xe1,0x89,0x26,0x98,0x39,0x0d,0x2c,0x03,0xec };
    const uint8_t IV[] = { 0x4d,0x05,0xbd,0xdb,0x59,0x13,0xcd,0xa5,0x7a,0x11,0x55,0x62,0x2a,0x43,0x74,0x76 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-40", "[CFB1][MCT][128][DECRYPT][n40]") {
    const uint8_t KEY[] = { 0x48,0xab,0x7c,0x10,0x97,0xd5,0x25,0xea,0x39,0x15,0x2e,0x60,0x04,0xc5,0xb0,0x99 };
    const uint8_t IV[] = { 0x51,0x94,0x67,0xde,0x14,0x95,0x2a,0x0b,0xb0,0x33,0xb6,0x59,0x09,0xe9,0xb3,0x75 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-41", "[CFB1][MCT][128][DECRYPT][n41]") {
    const uint8_t KEY[] = { 0x37,0x65,0x30,0xea,0x93,0xa5,0x1b,0x88,0x10,0x91,0xcc,0xae,0x4b,0x7e,0x6a,0x3f };
    const uint8_t IV[] = { 0x7f,0xce,0x4c,0xfa,0x04,0x70,0x3e,0x62,0x29,0x84,0xe2,0xce,0x4f,0xbb,0xda,0xa6 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-42", "[CFB1][MCT][128][DECRYPT][n42]") {
    const uint8_t KEY[] = { 0x8f,0xc9,0x63,0x67,0xa1,0x43,0xdc,0x55,0xce,0x1c,0x15,0x9b,0x7a,0x74,0x28,0x2f };
    const uint8_t IV[] = { 0xb8,0xac,0x53,0x8d,0x32,0xe6,0xc7,0xdd,0xde,0x8d,0xd9,0x35,0x31,0x0a,0x42,0x10 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-43", "[CFB1][MCT][128][DECRYPT][n43]") {
    const uint8_t KEY[] = { 0xf9,0xe2,0xa7,0x1a,0xf1,0x70,0xf1,0x60,0xbb,0x81,0xeb,0xb2,0xf5,0xcb,0x38,0xc9 };
    const uint8_t IV[] = { 0x76,0x2b,0xc4,0x7d,0x50,0x33,0x2d,0x35,0x75,0x9d,0xfe,0x29,0x8f,0xbf,0x10,0xe6 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-44", "[CFB1][MCT][128][DECRYPT][n44]") {
    const uint8_t KEY[] = { 0xbc,0x51,0x34,0x38,0xdb,0xe9,0xcf,0xdd,0xec,0xc6,0x74,0x70,0xc2,0x74,0x74,0x41 };
    const uint8_t IV[] = { 0x45,0xb3,0x93,0x22,0x2a,0x99,0x3e,0xbd,0x57,0x47,0x9f,0xc2,0x37,0xbf,0x4c,0x88 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-45", "[CFB1][MCT][128][DECRYPT][n45]") {
    const uint8_t KEY[] = { 0x41,0x0d,0x65,0x79,0xc2,0x0e,0xbe,0x62,0x9f,0x4b,0xe2,0x2e,0x51,0xfe,0x66,0xcd };
    const uint8_t IV[] = { 0xfd,0x5c,0x51,0x41,0x19,0xe7,0x71,0xbf,0x73,0x8d,0x96,0x5e,0x93,0x8a,0x12,0x8c };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-46", "[CFB1][MCT][128][DECRYPT][n46]") {
    const uint8_t KEY[] = { 0xbf,0x02,0x39,0x06,0x9c,0xa0,0x52,0xd9,0x61,0x21,0x94,0x94,0xb1,0x9c,0x35,0x0d };
    const uint8_t IV[] = { 0xfe,0x0f,0x5c,0x7f,0x5e,0xae,0xec,0xbb,0xfe,0x6a,0x76,0xba,0xe0,0x62,0x53,0xc0 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-47", "[CFB1][MCT][128][DECRYPT][n47]") {
    const uint8_t KEY[] = { 0x33,0x13,0xe2,0x7d,0xa8,0xec,0x18,0x7f,0x79,0xb2,0xb9,0x4e,0xec,0x26,0x51,0x17 };
    const uint8_t IV[] = { 0x8c,0x11,0xdb,0x7b,0x34,0x4c,0x4a,0xa6,0x18,0x93,0x2d,0xda,0x5d,0xba,0x64,0x1a };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-48", "[CFB1][MCT][128][DECRYPT][n48]") {
    const uint8_t KEY[] = { 0xb0,0x6e,0xd7,0x3e,0x42,0x82,0x55,0xfc,0xa2,0x6e,0x7e,0xcd,0x1b,0x1d,0x0a,0x9f };
    const uint8_t IV[] = { 0x83,0x7d,0x35,0x43,0xea,0x6e,0x4d,0x83,0xdb,0xdc,0xc7,0x83,0xf7,0x3b,0x5b,0x88 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-49", "[CFB1][MCT][128][DECRYPT][n49]") {
    const uint8_t KEY[] = { 0x98,0x1e,0x75,0x64,0xfc,0xa1,0x62,0x75,0x06,0xa6,0x07,0xe5,0xe1,0x87,0x13,0x0a };
    const uint8_t IV[] = { 0x28,0x70,0xa2,0x5a,0xbe,0x23,0x37,0x89,0xa4,0xc8,0x79,0x28,0xfa,0x9a,0x19,0x95 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-50", "[CFB1][MCT][128][DECRYPT][n50]") {
    const uint8_t KEY[] = { 0x1e,0x7e,0x07,0xd7,0xe3,0x06,0x22,0xbf,0xb3,0x98,0xdb,0x1d,0xf8,0x30,0xc7,0x5d };
    const uint8_t IV[] = { 0x86,0x60,0x72,0xb3,0x1f,0xa7,0x40,0xca,0xb5,0x3e,0xdc,0xf8,0x19,0xb7,0xd4,0x57 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-51", "[CFB1][MCT][128][DECRYPT][n51]") {
    const uint8_t KEY[] = { 0xbe,0x98,0x52,0x1c,0x61,0x1f,0x03,0x2c,0xa8,0x94,0x96,0x78,0xe9,0xb9,0x44,0xf5 };
    const uint8_t IV[] = { 0xa0,0xe6,0x55,0xcb,0x82,0x19,0x21,0x93,0x1b,0x0c,0x4d,0x65,0x11,0x89,0x83,0xa8 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-52", "[CFB1][MCT][128][DECRYPT][n52]") {
    const uint8_t KEY[] = { 0xdc,0x32,0x9c,0x42,0x08,0xba,0x6c,0x59,0x88,0x34,0xe1,0xa0,0xf2,0xba,0xfd,0x93 };
    const uint8_t IV[] = { 0x62,0xaa,0xce,0x5e,0x69,0xa5,0x6f,0x75,0x20,0xa0,0x77,0xd8,0x1b,0x03,0xb9,0x66 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-53", "[CFB1][MCT][128][DECRYPT][n53]") {
    const uint8_t KEY[] = { 0xb5,0xcb,0x4c,0x2e,0x29,0x1e,0x37,0x6f,0xf4,0x26,0x4c,0x25,0xc0,0x85,0xba,0x0f };
    const uint8_t IV[] = { 0x69,0xf9,0xd0,0x6c,0x21,0xa4,0x5b,0x36,0x7c,0x12,0xad,0x85,0x32,0x3f,0x47,0x9c };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-54", "[CFB1][MCT][128][DECRYPT][n54]") {
    const uint8_t KEY[] = { 0x49,0x69,0xc9,0xf3,0xcf,0xc8,0x35,0xa7,0x12,0x3f,0x50,0xef,0xc1,0x31,0x6e,0x46 };
    const uint8_t IV[] = { 0xfc,0xa2,0x85,0xdd,0xe6,0xd6,0x02,0xc8,0xe6,0x19,0x1c,0xca,0x01,0xb4,0xd4,0x49 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-55", "[CFB1][MCT][128][DECRYPT][n55]") {
    const uint8_t KEY[] = { 0xa6,0xbf,0xb1,0x60,0xed,0xd7,0xaf,0x56,0x7b,0x32,0x05,0x33,0x4d,0x3e,0x33,0x9c };
    const uint8_t IV[] = { 0xef,0xd6,0x78,0x93,0x22,0x1f,0x9a,0xf1,0x69,0x0d,0x55,0xdc,0x8c,0x0f,0x5d,0xda };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-56", "[CFB1][MCT][128][DECRYPT][n56]") {
    const uint8_t KEY[] = { 0x51,0xed,0xc1,0x72,0x6e,0xd6,0xde,0x0b,0x9b,0x20,0xa1,0xe1,0x3e,0x14,0xdd,0x66 };
    const uint8_t IV[] = { 0xf7,0x52,0x70,0x12,0x83,0x01,0x71,0x5d,0xe0,0x12,0xa4,0xd2,0x73,0x2a,0xee,0xfa };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-57", "[CFB1][MCT][128][DECRYPT][n57]") {
    const uint8_t KEY[] = { 0x44,0x47,0x13,0x55,0x4c,0xd5,0x6b,0x1d,0x33,0xc4,0x77,0x57,0xd5,0x16,0xed,0x23 };
    const uint8_t IV[] = { 0x15,0xaa,0xd2,0x27,0x22,0x03,0xb5,0x16,0xa8,0xe4,0xd6,0xb6,0xeb,0x02,0x30,0x45 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-58", "[CFB1][MCT][128][DECRYPT][n58]") {
    const uint8_t KEY[] = { 0x6c,0x76,0x0d,0xcb,0x41,0xd9,0x2e,0x86,0x43,0xe9,0x0e,0xe3,0xa9,0xb8,0xd6,0xb5 };
    const uint8_t IV[] = { 0x28,0x31,0x1e,0x9e,0x0d,0x0c,0x45,0x9b,0x70,0x2d,0x79,0xb4,0x7c,0xae,0x3b,0x96 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-59", "[CFB1][MCT][128][DECRYPT][n59]") {
    const uint8_t KEY[] = { 0x06,0x72,0xc5,0xd8,0xfa,0xcc,0xb3,0x9e,0xe2,0xb3,0x5b,0x77,0x4d,0xd1,0x6c,0xe4 };
    const uint8_t IV[] = { 0x6a,0x04,0xc8,0x13,0xbb,0x15,0x9d,0x18,0xa1,0x5a,0x55,0x94,0xe4,0x69,0xba,0x51 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-60", "[CFB1][MCT][128][DECRYPT][n60]") {
    const uint8_t KEY[] = { 0xa3,0xd8,0xed,0x90,0x08,0xc5,0x87,0x72,0xe3,0x94,0xb7,0x13,0xb7,0x33,0x98,0x93 };
    const uint8_t IV[] = { 0xa5,0xaa,0x28,0x48,0xf2,0x09,0x34,0xec,0x01,0x27,0xec,0x64,0xfa,0xe2,0xf4,0x77 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-61", "[CFB1][MCT][128][DECRYPT][n61]") {
    const uint8_t KEY[] = { 0x47,0x8d,0x61,0x86,0x1e,0xfa,0x7c,0x18,0xd7,0xac,0x6d,0xd9,0xc0,0x78,0x8d,0xb7 };
    const uint8_t IV[] = { 0xe4,0x55,0x8c,0x16,0x16,0x3f,0xfb,0x6a,0x34,0x38,0xda,0xca,0x77,0x4b,0x15,0x24 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-62", "[CFB1][MCT][128][DECRYPT][n62]") {
    const uint8_t KEY[] = { 0x3a,0xea,0x8f,0x53,0xef,0x76,0x44,0x40,0xf9,0xa7,0x81,0x57,0x99,0x98,0x04,0xf5 };
    const uint8_t IV[] = { 0x7d,0x67,0xee,0xd5,0xf1,0x8c,0x38,0x58,0x2e,0x0b,0xec,0x8e,0x59,0xe0,0x89,0x42 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-63", "[CFB1][MCT][128][DECRYPT][n63]") {
    const uint8_t KEY[] = { 0xa9,0x90,0x55,0x8b,0x07,0xd2,0x2d,0xcd,0x0e,0x36,0xa7,0x97,0x34,0x64,0x96,0x66 };
    const uint8_t IV[] = { 0x93,0x7a,0xda,0xd8,0xe8,0xa4,0x69,0x8d,0xf7,0x91,0x26,0xc0,0xad,0xfc,0x92,0x93 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-64", "[CFB1][MCT][128][DECRYPT][n64]") {
    const uint8_t KEY[] = { 0xf9,0x49,0xb4,0x4b,0xcf,0x33,0xb6,0x20,0x16,0xa6,0xe6,0x77,0xde,0xc0,0xc3,0x5b };
    const uint8_t IV[] = { 0x50,0xd9,0xe1,0xc0,0xc8,0xe1,0x9b,0xed,0x18,0x90,0x41,0xe0,0xea,0xa4,0x55,0x3d };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-65", "[CFB1][MCT][128][DECRYPT][n65]") {
    const uint8_t KEY[] = { 0xf9,0xd3,0xde,0xee,0x00,0xa8,0x9f,0x73,0xb2,0x5b,0x82,0x9d,0x59,0x05,0x0e,0x79 };
    const uint8_t IV[] = { 0x00,0x9a,0x6a,0xa5,0xcf,0x9b,0x29,0x53,0xa4,0xfd,0x64,0xea,0x87,0xc5,0xcd,0x22 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-66", "[CFB1][MCT][128][DECRYPT][n66]") {
    const uint8_t KEY[] = { 0x83,0x53,0x12,0x84,0x3e,0x71,0xd2,0x15,0xc8,0x84,0x9b,0x19,0x62,0xae,0xa1,0xa6 };
    const uint8_t IV[] = { 0x7a,0x80,0xcc,0x6a,0x3e,0xd9,0x4d,0x66,0x7a,0xdf,0x19,0x84,0x3b,0xab,0xaf,0xdf };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-67", "[CFB1][MCT][128][DECRYPT][n67]") {
    const uint8_t KEY[] = { 0xa7,0xc4,0x68,0x7a,0x4e,0x76,0xd5,0x8b,0xa7,0x67,0xd9,0x95,0x46,0xf9,0xf0,0xff };
    const uint8_t IV[] = { 0x24,0x97,0x7a,0xfe,0x70,0x07,0x07,0x9e,0x6f,0xe3,0x42,0x8c,0x24,0x57,0x51,0x59 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-68", "[CFB1][MCT][128][DECRYPT][n68]") {
    const uint8_t KEY[] = { 0x53,0xa0,0x43,0xe4,0xc2,0x26,0x13,0xa3,0x5d,0xe8,0x76,0x0e,0x33,0x92,0x80,0xcd };
    const uint8_t IV[] = { 0xf4,0x64,0x2b,0x9e,0x8c,0x50,0xc6,0x28,0xfa,0x8f,0xaf,0x9b,0x75,0x6b,0x70,0x32 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-69", "[CFB1][MCT][128][DECRYPT][n69]") {
    const uint8_t KEY[] = { 0x58,0x13,0x45,0x25,0x47,0xec,0xb5,0xbe,0x32,0x97,0x6b,0xb7,0x23,0xc4,0x89,0x07 };
    const uint8_t IV[] = { 0x0b,0xb3,0x06,0xc1,0x85,0xca,0xa6,0x1d,0x6f,0x7f,0x1d,0xb9,0x10,0x56,0x09,0xca };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-70", "[CFB1][MCT][128][DECRYPT][n70]") {
    const uint8_t KEY[] = { 0x55,0x80,0xb8,0xf3,0x81,0x9d,0x87,0x4d,0xa1,0xd6,0xd2,0x9e,0xc1,0x45,0xd1,0xd2 };
    const uint8_t IV[] = { 0x0d,0x93,0xfd,0xd6,0xc6,0x71,0x32,0xf3,0x93,0x41,0xb9,0x29,0xe2,0x81,0x58,0xd5 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-71", "[CFB1][MCT][128][DECRYPT][n71]") {
    const uint8_t KEY[] = { 0xcf,0x84,0x8b,0x0c,0x80,0x91,0x8f,0x92,0xda,0xc0,0x69,0xb7,0x06,0x0e,0xbb,0xe0 };
    const uint8_t IV[] = { 0x9a,0x04,0x33,0xff,0x01,0x0c,0x08,0xdf,0x7b,0x16,0xbb,0x29,0xc7,0x4b,0x6a,0x32 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-72", "[CFB1][MCT][128][DECRYPT][n72]") {
    const uint8_t KEY[] = { 0xeb,0xa4,0x5d,0x1a,0x99,0xba,0x0c,0x0b,0x45,0xff,0x3b,0xb1,0x62,0x5e,0xdc,0x9c };
    const uint8_t IV[] = { 0x24,0x20,0xd6,0x16,0x19,0x2b,0x83,0x99,0x9f,0x3f,0x52,0x06,0x64,0x50,0x67,0x7c };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-73", "[CFB1][MCT][128][DECRYPT][n73]") {
    const uint8_t KEY[] = { 0xb5,0xc5,0xd0,0xe4,0x66,0xe1,0x32,0xd4,0x6a,0x43,0x0b,0xd5,0xfd,0xd7,0x0b,0x6c };
    const uint8_t IV[] = { 0x5e,0x61,0x8d,0xfe,0xff,0x5b,0x3e,0xdf,0x2f,0xbc,0x30,0x64,0x9f,0x89,0xd7,0xf0 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-74", "[CFB1][MCT][128][DECRYPT][n74]") {
    const uint8_t KEY[] = { 0xa7,0x01,0xdc,0x9c,0x9a,0x89,0xd1,0x4a,0xc6,0x31,0x61,0x15,0x50,0x7d,0x2e,0x23 };
    const uint8_t IV[] = { 0x12,0xc4,0x0c,0x78,0xfc,0x68,0xe3,0x9e,0xac,0x72,0x6a,0xc0,0xad,0xaa,0x25,0x4f };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-75", "[CFB1][MCT][128][DECRYPT][n75]") {
    const uint8_t KEY[] = { 0x4b,0x5f,0x3e,0x85,0x56,0x90,0x8b,0xd6,0xb8,0x81,0xcc,0x0d,0x64,0xb2,0xe0,0x99 };
    const uint8_t IV[] = { 0xec,0x5e,0xe2,0x19,0xcc,0x19,0x5a,0x9c,0x7e,0xb0,0xad,0x18,0x34,0xcf,0xce,0xba };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-76", "[CFB1][MCT][128][DECRYPT][n76]") {
    const uint8_t KEY[] = { 0x0d,0x23,0x9b,0x50,0xef,0xd7,0x1a,0xcd,0xea,0x21,0xba,0xb7,0x41,0xfa,0x26,0xab };
    const uint8_t IV[] = { 0x46,0x7c,0xa5,0xd5,0xb9,0x47,0x91,0x1b,0x52,0xa0,0x76,0xba,0x25,0x48,0xc6,0x32 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-77", "[CFB1][MCT][128][DECRYPT][n77]") {
    const uint8_t KEY[] = { 0x21,0xb3,0xaf,0xec,0xbf,0x29,0x9b,0x9f,0x67,0x4d,0x73,0xa9,0x80,0x3a,0xf9,0xee };
    const uint8_t IV[] = { 0x2c,0x90,0x34,0xbc,0x50,0xfe,0x81,0x52,0x8d,0x6c,0xc9,0x1e,0xc1,0xc0,0xdf,0x45 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-78", "[CFB1][MCT][128][DECRYPT][n78]") {
    const uint8_t KEY[] = { 0x79,0x86,0x86,0xbc,0xe6,0x50,0x54,0x74,0xa3,0xd2,0x60,0x35,0x71,0xfb,0x46,0xf5 };
    const uint8_t IV[] = { 0x58,0x35,0x29,0x50,0x59,0x79,0xcf,0xeb,0xc4,0x9f,0x13,0x9c,0xf1,0xc1,0xbf,0x1b };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-79", "[CFB1][MCT][128][DECRYPT][n79]") {
    const uint8_t KEY[] = { 0xef,0x71,0xa7,0x64,0x1f,0x0c,0xb7,0x8c,0xd0,0xb5,0x28,0xde,0xfc,0xd5,0x13,0x34 };
    const uint8_t IV[] = { 0x96,0xf7,0x21,0xd8,0xf9,0x5c,0xe3,0xf8,0x73,0x67,0x48,0xeb,0x8d,0x2e,0x55,0xc1 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-80", "[CFB1][MCT][128][DECRYPT][n80]") {
    const uint8_t KEY[] = { 0x7d,0xab,0x3d,0xa7,0xb4,0xe5,0x16,0xaa,0xfd,0x9d,0x88,0xb1,0xea,0x09,0xe1,0xbc };
    const uint8_t IV[] = { 0x92,0xda,0x9a,0xc3,0xab,0xe9,0xa1,0x26,0x2d,0x28,0xa0,0x6f,0x16,0xdc,0xf2,0x88 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-81", "[CFB1][MCT][128][DECRYPT][n81]") {
    const uint8_t KEY[] = { 0xfc,0x8d,0x3b,0xbd,0x4c,0x82,0x54,0xba,0xc8,0xd9,0x63,0x06,0xf9,0xac,0xca,0xba };
    const uint8_t IV[] = { 0x81,0x26,0x06,0x1a,0xf8,0x67,0x42,0x10,0x35,0x44,0xeb,0xb7,0x13,0xa5,0x2b,0x06 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-82", "[CFB1][MCT][128][DECRYPT][n82]") {
    const uint8_t KEY[] = { 0x63,0x26,0x26,0xc1,0x74,0x28,0x0b,0x13,0x3f,0x18,0x2d,0x7d,0x22,0x1d,0xb3,0x9f };
    const uint8_t IV[] = { 0x9f,0xab,0x1d,0x7c,0x38,0xaa,0x5f,0xa9,0xf7,0xc1,0x4e,0x7b,0xdb,0xb1,0x79,0x25 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-83", "[CFB1][MCT][128][DECRYPT][n83]") {
    const uint8_t KEY[] = { 0x03,0xb8,0x33,0xba,0x9f,0xd7,0xdf,0x0f,0x69,0x6d,0x7e,0x7c,0xcc,0xe5,0xcf,0x23 };
    const uint8_t IV[] = { 0x60,0x9e,0x15,0x7b,0xeb,0xff,0xd4,0x1c,0x56,0x75,0x53,0x01,0xee,0xf8,0x7c,0xbc };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-84", "[CFB1][MCT][128][DECRYPT][n84]") {
    const uint8_t KEY[] = { 0x00,0xb1,0xdf,0xaa,0x91,0x03,0xc0,0xf3,0xe3,0xe8,0x6b,0x41,0x99,0x3a,0xf6,0x95 };
    const uint8_t IV[] = { 0x03,0x09,0xec,0x10,0x0e,0xd4,0x1f,0xfc,0x8a,0x85,0x15,0x3d,0x55,0xdf,0x39,0xb6 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-85", "[CFB1][MCT][128][DECRYPT][n85]") {
    const uint8_t KEY[] = { 0x07,0x3e,0x11,0xad,0xc7,0xbb,0x09,0x3a,0x76,0x04,0xaf,0xb4,0xd4,0x7b,0xfb,0xa1 };
    const uint8_t IV[] = { 0x07,0x8f,0xce,0x07,0x56,0xb8,0xc9,0xc9,0x95,0xec,0xc4,0xf5,0x4d,0x41,0x0d,0x34 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-86", "[CFB1][MCT][128][DECRYPT][n86]") {
    const uint8_t KEY[] = { 0x0b,0x30,0x1a,0x61,0x34,0x67,0x2a,0x52,0x4c,0x8f,0xc6,0x12,0x46,0xdb,0x69,0x83 };
    const uint8_t IV[] = { 0x0c,0x0e,0x0b,0xcc,0xf3,0xdc,0x23,0x68,0x3a,0x8b,0x69,0xa6,0x92,0xa0,0x92,0x22 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-87", "[CFB1][MCT][128][DECRYPT][n87]") {
    const uint8_t KEY[] = { 0x7d,0x48,0x3a,0xbc,0x94,0xbe,0x60,0xbd,0xdb,0x7c,0xae,0xac,0x9a,0x75,0xd8,0x98 };
    const uint8_t IV[] = { 0x76,0x78,0x20,0xdd,0xa0,0xd9,0x4a,0xef,0x97,0xf3,0x68,0xbe,0xdc,0xae,0xb1,0x1b };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-88", "[CFB1][MCT][128][DECRYPT][n88]") {
    const uint8_t KEY[] = { 0xf0,0x19,0x36,0xdc,0x28,0xa0,0x36,0xf0,0xd3,0xaf,0xb8,0xd1,0x79,0xee,0x05,0xb5 };
    const uint8_t IV[] = { 0x8d,0x51,0x0c,0x60,0xbc,0x1e,0x56,0x4d,0x08,0xd3,0x16,0x7d,0xe3,0x9b,0xdd,0x2d };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-89", "[CFB1][MCT][128][DECRYPT][n89]") {
    const uint8_t KEY[] = { 0x4c,0x27,0xef,0x72,0x6b,0xc6,0x29,0x02,0x03,0x4e,0x8b,0x06,0x3b,0xf5,0x6d,0xa3 };
    const uint8_t IV[] = { 0xbc,0x3e,0xd9,0xae,0x43,0x66,0x1f,0xf2,0xd0,0xe1,0x33,0xd7,0x42,0x1b,0x68,0x16 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-90", "[CFB1][MCT][128][DECRYPT][n90]") {
    const uint8_t KEY[] = { 0xe8,0x2d,0xa3,0x74,0xd9,0xb8,0x2c,0x64,0x31,0x25,0x6c,0x31,0xa3,0x7e,0xfe,0xf4 };
    const uint8_t IV[] = { 0xa4,0x0a,0x4c,0x06,0xb2,0x7e,0x05,0x66,0x32,0x6b,0xe7,0x37,0x98,0x8b,0x93,0x57 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-91", "[CFB1][MCT][128][DECRYPT][n91]") {
    const uint8_t KEY[] = { 0x2a,0x85,0x18,0x03,0xfd,0xc1,0x47,0xa7,0xe5,0x69,0xf6,0x21,0x04,0xbc,0x4b,0x37 };
    const uint8_t IV[] = { 0xc2,0xa8,0xbb,0x77,0x24,0x79,0x6b,0xc3,0xd4,0x4c,0x9a,0x10,0xa7,0xc2,0xb5,0xc3 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-92", "[CFB1][MCT][128][DECRYPT][n92]") {
    const uint8_t KEY[] = { 0x75,0xbc,0xa8,0x68,0xc5,0x1b,0x9f,0x02,0xc4,0x25,0x23,0xa1,0xfb,0xbd,0x8b,0x8a };
    const uint8_t IV[] = { 0x5f,0x39,0xb0,0x6b,0x38,0xda,0xd8,0xa5,0x21,0x4c,0xd5,0x80,0xff,0x01,0xc0,0xbd };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-93", "[CFB1][MCT][128][DECRYPT][n93]") {
    const uint8_t KEY[] = { 0x32,0x86,0x60,0x2b,0xe6,0x5f,0xa9,0xd0,0x61,0x07,0x6b,0x7f,0x5a,0xab,0xce,0x85 };
    const uint8_t IV[] = { 0x47,0x3a,0xc8,0x43,0x23,0x44,0x36,0xd2,0xa5,0x22,0x48,0xde,0xa1,0x16,0x45,0x0f };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-94", "[CFB1][MCT][128][DECRYPT][n94]") {
    const uint8_t KEY[] = { 0xd2,0x8f,0xd9,0xe8,0x50,0x3e,0x45,0xd6,0x76,0xda,0xe3,0x18,0x87,0x4f,0x69,0xb8 };
    const uint8_t IV[] = { 0xe0,0x09,0xb9,0xc3,0xb6,0x61,0xec,0x06,0x17,0xdd,0x88,0x67,0xdd,0xe4,0xa7,0x3d };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-95", "[CFB1][MCT][128][DECRYPT][n95]") {
    const uint8_t KEY[] = { 0x63,0x3a,0xf0,0xf3,0xd3,0x0f,0xc0,0xa8,0x57,0x95,0xc4,0x8b,0x58,0x69,0xae,0xdb };
    const uint8_t IV[] = { 0xb1,0xb5,0x29,0x1b,0x83,0x31,0x85,0x7e,0x21,0x4f,0x27,0x93,0xdf,0x26,0xc7,0x63 };
    const uint8_t PLAINTEXT[] = { 0x1 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-96", "[CFB1][MCT][128][DECRYPT][n96]") {
    const uint8_t KEY[] = { 0xb0,0x9e,0x31,0x92,0x33,0x66,0xd6,0xb5,0xc7,0x0d,0x3b,0x8e,0xbb,0x06,0x3e,0x04 };
    const uint8_t IV[] = { 0xd3,0xa4,0xc1,0x61,0xe0,0x69,0x16,0x1d,0x90,0x98,0xff,0x05,0xe3,0x6f,0x90,0xdf };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-97", "[CFB1][MCT][128][DECRYPT][n97]") {
    const uint8_t KEY[] = { 0xfe,0xe5,0x07,0x80,0x8b,0x01,0x8c,0x91,0xf6,0x96,0x62,0x04,0xb7,0x26,0xa2,0x96 };
    const uint8_t IV[] = { 0x4e,0x7b,0x36,0x12,0xb8,0x67,0x5a,0x24,0x31,0x9b,0x59,0x8a,0x0c,0x20,0x9c,0x92 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-98", "[CFB1][MCT][128][DECRYPT][n98]") {
    const uint8_t KEY[] = { 0xd2,0xb0,0x94,0x58,0xd3,0x46,0xed,0xe7,0xf5,0x6d,0x4e,0x81,0x01,0x5e,0x71,0x54 };
    const uint8_t IV[] = { 0x2c,0x55,0x93,0xd8,0x58,0x47,0x61,0x76,0x03,0xfb,0x2c,0x85,0xb6,0x78,0xd3,0xc2 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB1MCT128-DECRYPT-99", "[CFB1][MCT][128][DECRYPT][n99]") {
    const uint8_t KEY[] = { 0xc0,0x4a,0xce,0xdc,0x9c,0x93,0xe0,0xd1,0xdf,0xbb,0xf8,0x00,0x69,0xf0,0xbb,0x40 };
    const uint8_t IV[] = { 0x12,0xfa,0x5a,0x84,0x4f,0xd5,0x0d,0x36,0x2a,0xd6,0xb6,0x81,0x68,0xae,0xca,0x14 };
    const uint8_t PLAINTEXT[] = { 0x0 };
    const uint8_t CIPHERTEXT[] = { 0x1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb1(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb1(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

