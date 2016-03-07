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

TEST_CASE("CFB8MCT128-ENCRYPT-0", "[CFB8][MCT][128][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0x4f,0x13,0x9e,0x69,0xf5,0xf6,0xb8,0x12,0x58,0xfb,0x61,0x2e,0xfc,0x64,0x64,0xae };
    const uint8_t IV[] = { 0x15,0x0a,0xf9,0x36,0x12,0xb3,0x63,0x0f,0x89,0x8e,0x52,0xfe,0xbf,0x1e,0x4e,0x41 };
    const uint8_t PLAINTEXT[] = { 0xb7 };
    const uint8_t CIPHERTEXT[] = { 0xfa };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-1", "[CFB8][MCT][128][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0x9c,0x93,0x62,0x12,0x8a,0xdd,0x6c,0x91,0xc4,0x78,0x32,0x3a,0x3d,0x17,0xcf,0x54 };
    const uint8_t IV[] = { 0xd3,0x80,0xfc,0x7b,0x7f,0x2b,0xd4,0x83,0x9c,0x83,0x53,0x14,0xc1,0x73,0xab,0xfa };
    const uint8_t PLAINTEXT[] = { 0xd0 };
    const uint8_t CIPHERTEXT[] = { 0xea };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-2", "[CFB8][MCT][128][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0x4c,0xf4,0x92,0x6c,0xcc,0x7e,0xaa,0x05,0x5b,0x50,0x98,0x67,0x7f,0xf2,0x7f,0xbe };
    const uint8_t IV[] = { 0xd0,0x67,0xf0,0x7e,0x46,0xa3,0xc6,0x94,0x9f,0x28,0xaa,0x5d,0x42,0xe5,0xb0,0xea };
    const uint8_t PLAINTEXT[] = { 0xed };
    const uint8_t CIPHERTEXT[] = { 0x8d };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-3", "[CFB8][MCT][128][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0x9f,0x68,0x61,0x67,0x57,0xec,0x19,0x74,0xe8,0xe4,0x9c,0xf9,0x8e,0x9d,0x08,0x33 };
    const uint8_t IV[] = { 0xd3,0x9c,0xf3,0x0b,0x9b,0x92,0xb3,0x71,0xb3,0xb4,0x04,0x9e,0xf1,0x6f,0x77,0x8d };
    const uint8_t PLAINTEXT[] = { 0xf3 };
    const uint8_t CIPHERTEXT[] = { 0xdc };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-4", "[CFB8][MCT][128][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0x31,0x76,0xda,0x69,0x37,0xca,0xa8,0x55,0xbe,0xea,0x72,0x56,0x47,0x03,0xb7,0xef };
    const uint8_t IV[] = { 0xae,0x1e,0xbb,0x0e,0x60,0x26,0xb1,0x21,0x56,0x0e,0xee,0xaf,0xc9,0x9e,0xbf,0xdc };
    const uint8_t PLAINTEXT[] = { 0xbb };
    const uint8_t CIPHERTEXT[] = { 0xb9 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-5", "[CFB8][MCT][128][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0x9a,0x8b,0x47,0x57,0x7d,0xf1,0x86,0xa1,0x70,0xa4,0xdf,0xab,0x90,0x43,0x53,0x56 };
    const uint8_t IV[] = { 0xab,0xfd,0x9d,0x3e,0x4a,0x3b,0x2e,0xf4,0xce,0x4e,0xad,0xfd,0xd7,0x40,0xe4,0xb9 };
    const uint8_t PLAINTEXT[] = { 0x38 };
    const uint8_t CIPHERTEXT[] = { 0xf1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-6", "[CFB8][MCT][128][ENCRYPT][n6]") {
    const uint8_t KEY[] = { 0x2d,0xe7,0x5c,0x46,0xa7,0xf9,0x31,0x8d,0x3a,0xbb,0x00,0xfe,0xda,0xd7,0x1e,0xa7 };
    const uint8_t IV[] = { 0xb7,0x6c,0x1b,0x11,0xda,0x08,0xb7,0x2c,0x4a,0x1f,0xdf,0x55,0x4a,0x94,0x4d,0xf1 };
    const uint8_t PLAINTEXT[] = { 0x7d };
    const uint8_t CIPHERTEXT[] = { 0x1c };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-7", "[CFB8][MCT][128][ENCRYPT][n7]") {
    const uint8_t KEY[] = { 0x04,0x8a,0x6e,0xfc,0x36,0x05,0x7a,0x78,0x5e,0x96,0x36,0xe6,0x06,0x0a,0xbc,0xbb };
    const uint8_t IV[] = { 0x29,0x6d,0x32,0xba,0x91,0xfc,0x4b,0xf5,0x64,0x2d,0x36,0x18,0xdc,0xdd,0xa2,0x1c };
    const uint8_t PLAINTEXT[] = { 0x7f };
    const uint8_t CIPHERTEXT[] = { 0x60 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-8", "[CFB8][MCT][128][ENCRYPT][n8]") {
    const uint8_t KEY[] = { 0x24,0x1d,0x8b,0x72,0x7a,0xa9,0xc7,0xc5,0x7c,0x4d,0xa6,0x61,0x8c,0xfe,0x89,0xdb };
    const uint8_t IV[] = { 0x20,0x97,0xe5,0x8e,0x4c,0xac,0xbd,0xbd,0x22,0xdb,0x90,0x87,0x8a,0xf4,0x35,0x60 };
    const uint8_t PLAINTEXT[] = { 0x0e };
    const uint8_t CIPHERTEXT[] = { 0x6c };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-9", "[CFB8][MCT][128][ENCRYPT][n9]") {
    const uint8_t KEY[] = { 0x81,0x43,0xbe,0x15,0xf1,0x8a,0x24,0x60,0x13,0x1e,0xdf,0xff,0x27,0xa0,0x12,0xb7 };
    const uint8_t IV[] = { 0xa5,0x5e,0x35,0x67,0x8b,0x23,0xe3,0xa5,0x6f,0x53,0x79,0x9e,0xab,0x5e,0x9b,0x6c };
    const uint8_t PLAINTEXT[] = { 0x81 };
    const uint8_t CIPHERTEXT[] = { 0x9f };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-10", "[CFB8][MCT][128][ENCRYPT][n10]") {
    const uint8_t KEY[] = { 0x0e,0xac,0x8d,0x80,0x9b,0x20,0x74,0x02,0xaf,0xab,0xeb,0x5e,0x78,0x25,0xbe,0x28 };
    const uint8_t IV[] = { 0x8f,0xef,0x33,0x95,0x6a,0xaa,0x50,0x62,0xbc,0xb5,0x34,0xa1,0x5f,0x85,0xac,0x9f };
    const uint8_t PLAINTEXT[] = { 0x21 };
    const uint8_t CIPHERTEXT[] = { 0x85 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-11", "[CFB8][MCT][128][ENCRYPT][n11]") {
    const uint8_t KEY[] = { 0xe7,0xb9,0x7d,0xfb,0x7e,0x40,0x1d,0x73,0x4e,0x6a,0xc3,0xac,0x1b,0x8a,0x54,0xad };
    const uint8_t IV[] = { 0xe9,0x15,0xf0,0x7b,0xe5,0x60,0x69,0x71,0xe1,0xc1,0x28,0xf2,0x63,0xaf,0xea,0x85 };
    const uint8_t PLAINTEXT[] = { 0x75 };
    const uint8_t CIPHERTEXT[] = { 0x39 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-12", "[CFB8][MCT][128][ENCRYPT][n12]") {
    const uint8_t KEY[] = { 0x58,0x34,0x31,0x9c,0x89,0x36,0x36,0x25,0xf7,0x85,0xdd,0xd5,0x68,0x8f,0xce,0x94 };
    const uint8_t IV[] = { 0xbf,0x8d,0x4c,0x67,0xf7,0x76,0x2b,0x56,0xb9,0xef,0x1e,0x79,0x73,0x05,0x9a,0x39 };
    const uint8_t PLAINTEXT[] = { 0xd6 };
    const uint8_t CIPHERTEXT[] = { 0x75 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-13", "[CFB8][MCT][128][ENCRYPT][n13]") {
    const uint8_t KEY[] = { 0xdd,0x10,0xd1,0xe7,0x8f,0x67,0x34,0x86,0x63,0xe6,0xc9,0x6b,0xb7,0x9c,0xec,0xe1 };
    const uint8_t IV[] = { 0x85,0x24,0xe0,0x7b,0x06,0x51,0x02,0xa3,0x94,0x63,0x14,0xbe,0xdf,0x13,0x22,0x75 };
    const uint8_t PLAINTEXT[] = { 0x45 };
    const uint8_t CIPHERTEXT[] = { 0xcd };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-14", "[CFB8][MCT][128][ENCRYPT][n14]") {
    const uint8_t KEY[] = { 0xc2,0x51,0x67,0x5a,0x60,0x11,0xc3,0xd3,0xe1,0x3f,0x1d,0x18,0xed,0xd8,0xf6,0x2c };
    const uint8_t IV[] = { 0x1f,0x41,0xb6,0xbd,0xef,0x76,0xf7,0x55,0x82,0xd9,0xd4,0x73,0x5a,0x44,0x1a,0xcd };
    const uint8_t PLAINTEXT[] = { 0x33 };
    const uint8_t CIPHERTEXT[] = { 0x21 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-15", "[CFB8][MCT][128][ENCRYPT][n15]") {
    const uint8_t KEY[] = { 0xe6,0xf8,0x56,0xa8,0x13,0x0c,0x65,0x75,0xec,0x31,0x55,0x76,0xf0,0x4e,0xcc,0x0d };
    const uint8_t IV[] = { 0x24,0xa9,0x31,0xf2,0x73,0x1d,0xa6,0xa6,0x0d,0x0e,0x48,0x6e,0x1d,0x96,0x3a,0x21 };
    const uint8_t PLAINTEXT[] = { 0x00 };
    const uint8_t CIPHERTEXT[] = { 0xdf };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-16", "[CFB8][MCT][128][ENCRYPT][n16]") {
    const uint8_t KEY[] = { 0x1d,0x45,0xcd,0x04,0x57,0x3e,0xae,0xeb,0xb8,0x46,0x71,0x88,0x25,0x86,0x29,0xd2 };
    const uint8_t IV[] = { 0xfb,0xbd,0x9b,0xac,0x44,0x32,0xcb,0x9e,0x54,0x77,0x24,0xfe,0xd5,0xc8,0xe5,0xdf };
    const uint8_t PLAINTEXT[] = { 0x4e };
    const uint8_t CIPHERTEXT[] = { 0x8b };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-17", "[CFB8][MCT][128][ENCRYPT][n17]") {
    const uint8_t KEY[] = { 0x1f,0xb2,0x0a,0xba,0x55,0x2a,0xb5,0xa5,0x59,0x19,0x72,0x2a,0xeb,0x8a,0x33,0x59 };
    const uint8_t IV[] = { 0x02,0xf7,0xc7,0xbe,0x02,0x14,0x1b,0x4e,0xe1,0x5f,0x03,0xa2,0xce,0x0c,0x1a,0x8b };
    const uint8_t PLAINTEXT[] = { 0x8e };
    const uint8_t CIPHERTEXT[] = { 0x66 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-18", "[CFB8][MCT][128][ENCRYPT][n18]") {
    const uint8_t KEY[] = { 0x9c,0xde,0x67,0x36,0x18,0x7d,0x8f,0x8f,0xab,0xfe,0x5c,0x40,0x47,0x6a,0xa3,0x3f };
    const uint8_t IV[] = { 0x83,0x6c,0x6d,0x8c,0x4d,0x57,0x3a,0x2a,0xf2,0xe7,0x2e,0x6a,0xac,0xe0,0x90,0x66 };
    const uint8_t PLAINTEXT[] = { 0x51 };
    const uint8_t CIPHERTEXT[] = { 0x87 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-19", "[CFB8][MCT][128][ENCRYPT][n19]") {
    const uint8_t KEY[] = { 0x80,0x25,0x80,0xdf,0xd0,0x30,0x58,0x8a,0x35,0x43,0x3a,0x36,0xf0,0x1a,0x79,0xb8 };
    const uint8_t IV[] = { 0x1c,0xfb,0xe7,0xe9,0xc8,0x4d,0xd7,0x05,0x9e,0xbd,0x66,0x76,0xb7,0x70,0xda,0x87 };
    const uint8_t PLAINTEXT[] = { 0xe6 };
    const uint8_t CIPHERTEXT[] = { 0x3e };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-20", "[CFB8][MCT][128][ENCRYPT][n20]") {
    const uint8_t KEY[] = { 0x08,0xab,0x18,0x7d,0x0d,0x82,0xfd,0xe8,0x0e,0x23,0x7e,0xfb,0x8f,0x5a,0x2c,0x86 };
    const uint8_t IV[] = { 0x88,0x8e,0x98,0xa2,0xdd,0xb2,0xa5,0x62,0x3b,0x60,0x44,0xcd,0x7f,0x40,0x55,0x3e };
    const uint8_t PLAINTEXT[] = { 0xde };
    const uint8_t CIPHERTEXT[] = { 0x83 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-21", "[CFB8][MCT][128][ENCRYPT][n21]") {
    const uint8_t KEY[] = { 0x41,0x86,0x6c,0xdf,0xd1,0x8a,0xc7,0xbc,0xd1,0x11,0x46,0x75,0xbc,0xac,0x41,0x05 };
    const uint8_t IV[] = { 0x49,0x2d,0x74,0xa2,0xdc,0x08,0x3a,0x54,0xdf,0x32,0x38,0x8e,0x33,0xf6,0x6d,0x83 };
    const uint8_t PLAINTEXT[] = { 0x6d };
    const uint8_t CIPHERTEXT[] = { 0x5e };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-22", "[CFB8][MCT][128][ENCRYPT][n22]") {
    const uint8_t KEY[] = { 0xc0,0xb6,0xa8,0x13,0xa8,0x3e,0x45,0x77,0x7c,0x67,0x15,0x51,0x30,0xda,0x19,0x5b };
    const uint8_t IV[] = { 0x81,0x30,0xc4,0xcc,0x79,0xb4,0x82,0xcb,0xad,0x76,0x53,0x24,0x8c,0x76,0x58,0x5e };
    const uint8_t PLAINTEXT[] = { 0x18 };
    const uint8_t CIPHERTEXT[] = { 0xb5 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-23", "[CFB8][MCT][128][ENCRYPT][n23]") {
    const uint8_t KEY[] = { 0xa0,0x6f,0x5f,0xfa,0x8e,0x7c,0xb9,0xfc,0xcf,0x18,0xe2,0x7f,0x63,0x84,0x0f,0xee };
    const uint8_t IV[] = { 0x60,0xd9,0xf7,0xe9,0x26,0x42,0xfc,0x8b,0xb3,0x7f,0xf7,0x2e,0x53,0x5e,0x16,0xb5 };
    const uint8_t PLAINTEXT[] = { 0xaa };
    const uint8_t CIPHERTEXT[] = { 0xea };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-24", "[CFB8][MCT][128][ENCRYPT][n24]") {
    const uint8_t KEY[] = { 0x71,0x28,0x55,0xed,0x20,0x80,0x99,0x87,0xc9,0xe6,0xe7,0xb1,0xa5,0xb0,0xb4,0x04 };
    const uint8_t IV[] = { 0xd1,0x47,0x0a,0x17,0xae,0xfc,0x20,0x7b,0x06,0xfe,0x05,0xce,0xc6,0x34,0xbb,0xea };
    const uint8_t PLAINTEXT[] = { 0x61 };
    const uint8_t CIPHERTEXT[] = { 0x0f };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-25", "[CFB8][MCT][128][ENCRYPT][n25]") {
    const uint8_t KEY[] = { 0xeb,0x65,0x06,0xb8,0x31,0x3d,0xa4,0x2e,0xd0,0x4a,0xf0,0xc7,0x69,0x55,0xdf,0x0b };
    const uint8_t IV[] = { 0x9a,0x4d,0x53,0x55,0x11,0xbd,0x3d,0xa9,0x19,0xac,0x17,0x76,0xcc,0xe5,0x6b,0x0f };
    const uint8_t PLAINTEXT[] = { 0x18 };
    const uint8_t CIPHERTEXT[] = { 0x51 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-26", "[CFB8][MCT][128][ENCRYPT][n26]") {
    const uint8_t KEY[] = { 0xe1,0x8c,0x56,0xd0,0x3f,0x28,0xe4,0x06,0x3a,0xfc,0x54,0x1b,0x65,0xaf,0xe2,0x5a };
    const uint8_t IV[] = { 0x0a,0xe9,0x50,0x68,0x0e,0x15,0x40,0x28,0xea,0xb6,0xa4,0xdc,0x0c,0xfa,0x3d,0x51 };
    const uint8_t PLAINTEXT[] = { 0xc9 };
    const uint8_t CIPHERTEXT[] = { 0x3c };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-27", "[CFB8][MCT][128][ENCRYPT][n27]") {
    const uint8_t KEY[] = { 0x39,0x9a,0xdf,0x82,0x66,0xe4,0x2f,0xcc,0x86,0x91,0x93,0x94,0x78,0x37,0xbc,0x66 };
    const uint8_t IV[] = { 0xd8,0x16,0x89,0x52,0x59,0xcc,0xcb,0xca,0xbc,0x6d,0xc7,0x8f,0x1d,0x98,0x5e,0x3c };
    const uint8_t PLAINTEXT[] = { 0x4d };
    const uint8_t CIPHERTEXT[] = { 0x91 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-28", "[CFB8][MCT][128][ENCRYPT][n28]") {
    const uint8_t KEY[] = { 0x46,0xa2,0xf1,0x8a,0x0a,0xee,0xbb,0xfe,0xb1,0x14,0x8d,0xc4,0x03,0x3b,0xa2,0xf7 };
    const uint8_t IV[] = { 0x7f,0x38,0x2e,0x08,0x6c,0x0a,0x94,0x32,0x37,0x85,0x1e,0x50,0x7b,0x0c,0x1e,0x91 };
    const uint8_t PLAINTEXT[] = { 0x15 };
    const uint8_t CIPHERTEXT[] = { 0xc8 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-29", "[CFB8][MCT][128][ENCRYPT][n29]") {
    const uint8_t KEY[] = { 0x81,0x1e,0xaf,0x94,0x0a,0x77,0x09,0xd1,0x93,0x8f,0xd8,0x3f,0xab,0xa1,0xdf,0x3f };
    const uint8_t IV[] = { 0xc7,0xbc,0x5e,0x1e,0x00,0x99,0xb2,0x2f,0x22,0x9b,0x55,0xfb,0xa8,0x9a,0x7d,0xc8 };
    const uint8_t PLAINTEXT[] = { 0x93 };
    const uint8_t CIPHERTEXT[] = { 0x49 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-30", "[CFB8][MCT][128][ENCRYPT][n30]") {
    const uint8_t KEY[] = { 0x6a,0xe5,0xa7,0xed,0xe9,0xbc,0x29,0xdb,0x5c,0x4f,0x87,0xec,0x90,0x2d,0x3f,0x76 };
    const uint8_t IV[] = { 0xeb,0xfb,0x08,0x79,0xe3,0xcb,0x20,0x0a,0xcf,0xc0,0x5f,0xd3,0x3b,0x8c,0xe0,0x49 };
    const uint8_t PLAINTEXT[] = { 0xf8 };
    const uint8_t CIPHERTEXT[] = { 0x43 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-31", "[CFB8][MCT][128][ENCRYPT][n31]") {
    const uint8_t KEY[] = { 0x4e,0x8b,0x73,0x91,0xd9,0xfb,0x5f,0xdf,0xf5,0xa2,0x0d,0x40,0xf5,0xf7,0x6c,0x35 };
    const uint8_t IV[] = { 0x24,0x6e,0xd4,0x7c,0x30,0x47,0x76,0x04,0xa9,0xed,0x8a,0xac,0x65,0xda,0x53,0x43 };
    const uint8_t PLAINTEXT[] = { 0x86 };
    const uint8_t CIPHERTEXT[] = { 0x66 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-32", "[CFB8][MCT][128][ENCRYPT][n32]") {
    const uint8_t KEY[] = { 0x07,0x41,0x19,0x9b,0xcf,0xb3,0x97,0x86,0xfe,0x9d,0xfd,0x34,0x65,0xe8,0x2d,0x53 };
    const uint8_t IV[] = { 0x49,0xca,0x6a,0x0a,0x16,0x48,0xc8,0x59,0x0b,0x3f,0xf0,0x74,0x90,0x1f,0x41,0x66 };
    const uint8_t PLAINTEXT[] = { 0x2e };
    const uint8_t CIPHERTEXT[] = { 0x87 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-33", "[CFB8][MCT][128][ENCRYPT][n33]") {
    const uint8_t KEY[] = { 0xba,0x1e,0x81,0x49,0x8e,0x9c,0x89,0x95,0xb9,0xf6,0x7b,0x2e,0xd2,0x37,0x44,0xd4 };
    const uint8_t IV[] = { 0xbd,0x5f,0x98,0xd2,0x41,0x2f,0x1e,0x13,0x47,0x6b,0x86,0x1a,0xb7,0xdf,0x69,0x87 };
    const uint8_t PLAINTEXT[] = { 0x2a };
    const uint8_t CIPHERTEXT[] = { 0xac };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-34", "[CFB8][MCT][128][ENCRYPT][n34]") {
    const uint8_t KEY[] = { 0x96,0x63,0x65,0x4b,0x5a,0xc4,0x29,0xe5,0x3b,0xb6,0x76,0x61,0x1d,0x02,0xc9,0x78 };
    const uint8_t IV[] = { 0x2c,0x7d,0xe4,0x02,0xd4,0x58,0xa0,0x70,0x82,0x40,0x0d,0x4f,0xcf,0x35,0x8d,0xac };
    const uint8_t PLAINTEXT[] = { 0x2b };
    const uint8_t CIPHERTEXT[] = { 0xe4 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-35", "[CFB8][MCT][128][ENCRYPT][n35]") {
    const uint8_t KEY[] = { 0x56,0x62,0xbd,0xbf,0x85,0xeb,0xd2,0x82,0x54,0x7e,0x27,0x2d,0xae,0x6a,0xa9,0x9c };
    const uint8_t IV[] = { 0xc0,0x01,0xd8,0xf4,0xdf,0x2f,0xfb,0x67,0x6f,0xc8,0x51,0x4c,0xb3,0x68,0x60,0xe4 };
    const uint8_t PLAINTEXT[] = { 0x0f };
    const uint8_t CIPHERTEXT[] = { 0x75 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-36", "[CFB8][MCT][128][ENCRYPT][n36]") {
    const uint8_t KEY[] = { 0x60,0x22,0xfd,0x83,0xd5,0x1a,0xbc,0x0b,0xba,0xc5,0xe8,0x70,0x1e,0x85,0x21,0xe9 };
    const uint8_t IV[] = { 0x36,0x40,0x40,0x3c,0x50,0xf1,0x6e,0x89,0xee,0xbb,0xcf,0x5d,0xb0,0xef,0x88,0x75 };
    const uint8_t PLAINTEXT[] = { 0x83 };
    const uint8_t CIPHERTEXT[] = { 0x60 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-37", "[CFB8][MCT][128][ENCRYPT][n37]") {
    const uint8_t KEY[] = { 0x94,0x9e,0x03,0xa7,0xfe,0x0d,0x71,0x5d,0x74,0x6a,0xb3,0xda,0x93,0x86,0x9a,0x89 };
    const uint8_t IV[] = { 0xf4,0xbc,0xfe,0x24,0x2b,0x17,0xcd,0x56,0xce,0xaf,0x5b,0xaa,0x8d,0x03,0xbb,0x60 };
    const uint8_t PLAINTEXT[] = { 0x4d };
    const uint8_t CIPHERTEXT[] = { 0xec };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-38", "[CFB8][MCT][128][ENCRYPT][n38]") {
    const uint8_t KEY[] = { 0xbb,0x7d,0xd1,0x2d,0x43,0x4f,0x63,0x3d,0xa0,0x9d,0xee,0xbc,0xa7,0x41,0xe4,0x65 };
    const uint8_t IV[] = { 0x2f,0xe3,0xd2,0x8a,0xbd,0x42,0x12,0x60,0xd4,0xf7,0x5d,0x66,0x34,0xc7,0x7e,0xec };
    const uint8_t PLAINTEXT[] = { 0x22 };
    const uint8_t CIPHERTEXT[] = { 0x5b };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-39", "[CFB8][MCT][128][ENCRYPT][n39]") {
    const uint8_t KEY[] = { 0x96,0xe5,0x56,0xe1,0x68,0xfb,0xd7,0xad,0xe2,0x2d,0x6f,0x37,0x78,0x0f,0x79,0x3e };
    const uint8_t IV[] = { 0x2d,0x98,0x87,0xcc,0x2b,0xb4,0xb4,0x90,0x42,0xb0,0x81,0x8b,0xdf,0x4e,0x9d,0x5b };
    const uint8_t PLAINTEXT[] = { 0x0a };
    const uint8_t CIPHERTEXT[] = { 0xea };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-40", "[CFB8][MCT][128][ENCRYPT][n40]") {
    const uint8_t KEY[] = { 0x89,0xf2,0x4d,0x2a,0x5a,0x0f,0x51,0x52,0x16,0x11,0x66,0x33,0x3e,0xa1,0xc3,0xd4 };
    const uint8_t IV[] = { 0x1f,0x17,0x1b,0xcb,0x32,0xf4,0x86,0xff,0xf4,0x3c,0x09,0x04,0x46,0xae,0xba,0xea };
    const uint8_t PLAINTEXT[] = { 0xf1 };
    const uint8_t CIPHERTEXT[] = { 0x55 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-41", "[CFB8][MCT][128][ENCRYPT][n41]") {
    const uint8_t KEY[] = { 0x60,0xfe,0x29,0x70,0xbb,0x63,0x48,0xc0,0x45,0xec,0x6f,0xa7,0x12,0x81,0x83,0x81 };
    const uint8_t IV[] = { 0xe9,0x0c,0x64,0x5a,0xe1,0x6c,0x19,0x92,0x53,0xfd,0x09,0x94,0x2c,0x20,0x40,0x55 };
    const uint8_t PLAINTEXT[] = { 0xbf };
    const uint8_t CIPHERTEXT[] = { 0x90 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-42", "[CFB8][MCT][128][ENCRYPT][n42]") {
    const uint8_t KEY[] = { 0x78,0xc8,0xd9,0x59,0x76,0xf2,0x85,0xb4,0x23,0x70,0xac,0x89,0xde,0xeb,0xa1,0x11 };
    const uint8_t IV[] = { 0x18,0x36,0xf0,0x29,0xcd,0x91,0xcd,0x74,0x66,0x9c,0xc3,0x2e,0xcc,0x6a,0x22,0x90 };
    const uint8_t PLAINTEXT[] = { 0x4e };
    const uint8_t CIPHERTEXT[] = { 0x5c };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-43", "[CFB8][MCT][128][ENCRYPT][n43]") {
    const uint8_t KEY[] = { 0x5f,0xa9,0xc0,0xc5,0xd7,0xd4,0x98,0x4d,0x75,0xe1,0x2a,0x7a,0xea,0x04,0xec,0x4d };
    const uint8_t IV[] = { 0x27,0x61,0x19,0x9c,0xa1,0x26,0x1d,0xf9,0x56,0x91,0x86,0xf3,0x34,0xef,0x4d,0x5c };
    const uint8_t PLAINTEXT[] = { 0xaa };
    const uint8_t CIPHERTEXT[] = { 0x54 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-44", "[CFB8][MCT][128][ENCRYPT][n44]") {
    const uint8_t KEY[] = { 0xaa,0x45,0x77,0x41,0x17,0x23,0xd0,0x50,0x5e,0x4f,0xe7,0x6e,0x13,0x4a,0xd3,0x19 };
    const uint8_t IV[] = { 0xf5,0xec,0xb7,0x84,0xc0,0xf7,0x48,0x1d,0x2b,0xae,0xcd,0x14,0xf9,0x4e,0x3f,0x54 };
    const uint8_t PLAINTEXT[] = { 0x28 };
    const uint8_t CIPHERTEXT[] = { 0x13 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-45", "[CFB8][MCT][128][ENCRYPT][n45]") {
    const uint8_t KEY[] = { 0x49,0x05,0x93,0x1f,0x97,0x75,0x73,0xa8,0x64,0x9a,0x6f,0x35,0xb9,0xac,0xe8,0x0a };
    const uint8_t IV[] = { 0xe3,0x40,0xe4,0x5e,0x80,0x56,0xa3,0xf8,0x3a,0xd5,0x88,0x5b,0xaa,0xe6,0x3b,0x13 };
    const uint8_t PLAINTEXT[] = { 0xae };
    const uint8_t CIPHERTEXT[] = { 0x41 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-46", "[CFB8][MCT][128][ENCRYPT][n46]") {
    const uint8_t KEY[] = { 0xba,0x65,0xb1,0x28,0xa3,0xb8,0x9b,0x0d,0x5e,0x08,0xce,0x9f,0x84,0x2e,0x1c,0x4b };
    const uint8_t IV[] = { 0xf3,0x60,0x22,0x37,0x34,0xcd,0xe8,0xa5,0x3a,0x92,0xa1,0xaa,0x3d,0x82,0xf4,0x41 };
    const uint8_t PLAINTEXT[] = { 0x07 };
    const uint8_t CIPHERTEXT[] = { 0x9a };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-47", "[CFB8][MCT][128][ENCRYPT][n47]") {
    const uint8_t KEY[] = { 0x3b,0xde,0xab,0x5d,0xda,0x3e,0x8b,0xc5,0x29,0x40,0x76,0x20,0x07,0xca,0x1e,0xd1 };
    const uint8_t IV[] = { 0x81,0xbb,0x1a,0x75,0x79,0x86,0x10,0xc8,0x77,0x48,0xb8,0xbf,0x83,0xe4,0x02,0x9a };
    const uint8_t PLAINTEXT[] = { 0x6c };
    const uint8_t CIPHERTEXT[] = { 0x09 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-48", "[CFB8][MCT][128][ENCRYPT][n48]") {
    const uint8_t KEY[] = { 0xba,0xc0,0x93,0xcd,0x0c,0xc0,0x4c,0x6e,0xea,0xb7,0x96,0xbe,0xfa,0x9e,0xa4,0xd8 };
    const uint8_t IV[] = { 0x81,0x1e,0x38,0x90,0xd6,0xfe,0xc7,0xab,0xc3,0xf7,0xe0,0x9e,0xfd,0x54,0xba,0x09 };
    const uint8_t PLAINTEXT[] = { 0x8b };
    const uint8_t CIPHERTEXT[] = { 0xa8 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-49", "[CFB8][MCT][128][ENCRYPT][n49]") {
    const uint8_t KEY[] = { 0x5b,0x54,0x58,0x56,0x48,0xe3,0x91,0xd3,0x13,0x56,0xae,0xae,0x10,0xae,0xf8,0x70 };
    const uint8_t IV[] = { 0xe1,0x94,0xcb,0x9b,0x44,0x23,0xdd,0xbd,0xf9,0xe1,0x38,0x10,0xea,0x30,0x5c,0xa8 };
    const uint8_t PLAINTEXT[] = { 0x6d };
    const uint8_t CIPHERTEXT[] = { 0x2a };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-50", "[CFB8][MCT][128][ENCRYPT][n50]") {
    const uint8_t KEY[] = { 0xed,0x8b,0x0e,0x55,0x87,0xbb,0xf1,0xd7,0xdc,0x80,0xf9,0x4a,0x9d,0x17,0xaf,0x5a };
    const uint8_t IV[] = { 0xb6,0xdf,0x56,0x03,0xcf,0x58,0x60,0x04,0xcf,0xd6,0x57,0xe4,0x8d,0xb9,0x57,0x2a };
    const uint8_t PLAINTEXT[] = { 0x20 };
    const uint8_t CIPHERTEXT[] = { 0xc8 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-51", "[CFB8][MCT][128][ENCRYPT][n51]") {
    const uint8_t KEY[] = { 0xd0,0x60,0xe6,0x4f,0xce,0x10,0xa8,0xf4,0x2d,0xfd,0x3a,0x96,0xcb,0x24,0xcd,0x92 };
    const uint8_t IV[] = { 0x3d,0xeb,0xe8,0x1a,0x49,0xab,0x59,0x23,0xf1,0x7d,0xc3,0xdc,0x56,0x33,0x62,0xc8 };
    const uint8_t PLAINTEXT[] = { 0xeb };
    const uint8_t CIPHERTEXT[] = { 0x96 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-52", "[CFB8][MCT][128][ENCRYPT][n52]") {
    const uint8_t KEY[] = { 0x12,0x41,0xb3,0xfd,0x8f,0x01,0xfd,0x41,0x90,0x57,0xcb,0xc4,0x3a,0xdd,0xaf,0x04 };
    const uint8_t IV[] = { 0xc2,0x21,0x55,0xb2,0x41,0x11,0x55,0xb5,0xbd,0xaa,0xf1,0x52,0xf1,0xf9,0x62,0x96 };
    const uint8_t PLAINTEXT[] = { 0x4d };
    const uint8_t CIPHERTEXT[] = { 0xdf };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-53", "[CFB8][MCT][128][ENCRYPT][n53]") {
    const uint8_t KEY[] = { 0xc3,0x0d,0xee,0x40,0x94,0x11,0x8f,0xb8,0xb3,0xc4,0x24,0xc7,0x28,0x6b,0x07,0xdb };
    const uint8_t IV[] = { 0xd1,0x4c,0x5d,0xbd,0x1b,0x10,0x72,0xf9,0x23,0x93,0xef,0x03,0x12,0xb6,0xa8,0xdf };
    const uint8_t PLAINTEXT[] = { 0xaa };
    const uint8_t CIPHERTEXT[] = { 0x6f };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-54", "[CFB8][MCT][128][ENCRYPT][n54]") {
    const uint8_t KEY[] = { 0xe8,0x53,0x3b,0x29,0x47,0x0a,0x9f,0x73,0xa1,0x41,0xbb,0xfb,0xf7,0xaf,0x4b,0xb4 };
    const uint8_t IV[] = { 0x2b,0x5e,0xd5,0x69,0xd3,0x1b,0x10,0xcb,0x12,0x85,0x9f,0x3c,0xdf,0xc4,0x4c,0x6f };
    const uint8_t PLAINTEXT[] = { 0xa3 };
    const uint8_t CIPHERTEXT[] = { 0x04 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-55", "[CFB8][MCT][128][ENCRYPT][n55]") {
    const uint8_t KEY[] = { 0xb4,0x58,0xb3,0x75,0x54,0xc2,0x43,0x4e,0x22,0xef,0xf8,0xb4,0x34,0xe5,0xd4,0xb0 };
    const uint8_t IV[] = { 0x5c,0x0b,0x88,0x5c,0x13,0xc8,0xdc,0x3d,0x83,0xae,0x43,0x4f,0xc3,0x4a,0x9f,0x04 };
    const uint8_t PLAINTEXT[] = { 0x05 };
    const uint8_t CIPHERTEXT[] = { 0x39 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-56", "[CFB8][MCT][128][ENCRYPT][n56]") {
    const uint8_t KEY[] = { 0xc7,0xb6,0xb7,0x87,0x41,0xeb,0x3d,0xc2,0x09,0x66,0x60,0xba,0xfc,0xd6,0x3f,0x89 };
    const uint8_t IV[] = { 0x73,0xee,0x04,0xf2,0x15,0x29,0x7e,0x8c,0x2b,0x89,0x98,0x0e,0xc8,0x33,0xeb,0x39 };
    const uint8_t PLAINTEXT[] = { 0x2b };
    const uint8_t CIPHERTEXT[] = { 0xee };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-57", "[CFB8][MCT][128][ENCRYPT][n57]") {
    const uint8_t KEY[] = { 0x3b,0x99,0x03,0xb8,0xa9,0x26,0x53,0xa3,0xba,0x7e,0x54,0xe2,0xa1,0x6e,0xe4,0x67 };
    const uint8_t IV[] = { 0xfc,0x2f,0xb4,0x3f,0xe8,0xcd,0x6e,0x61,0xb3,0x18,0x34,0x58,0x5d,0xb8,0xdb,0xee };
    const uint8_t PLAINTEXT[] = { 0x3b };
    const uint8_t CIPHERTEXT[] = { 0x8a };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-58", "[CFB8][MCT][128][ENCRYPT][n58]") {
    const uint8_t KEY[] = { 0x34,0xde,0x8b,0x10,0xc3,0x4c,0x14,0xb0,0x9b,0xd1,0x61,0xc3,0x89,0x35,0x9c,0xed };
    const uint8_t IV[] = { 0x0f,0x47,0x88,0xa8,0x6a,0x6a,0x47,0x13,0x21,0xaf,0x35,0x21,0x28,0x5b,0x78,0x8a };
    const uint8_t PLAINTEXT[] = { 0x6b };
    const uint8_t CIPHERTEXT[] = { 0x40 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-59", "[CFB8][MCT][128][ENCRYPT][n59]") {
    const uint8_t KEY[] = { 0xdc,0xc1,0xf5,0xd8,0x2e,0x84,0xdd,0x27,0x4d,0x94,0x9f,0xfd,0xaa,0x60,0x71,0xad };
    const uint8_t IV[] = { 0xe8,0x1f,0x7e,0xc8,0xed,0xc8,0xc9,0x97,0xd6,0x45,0xfe,0x3e,0x23,0x55,0xed,0x40 };
    const uint8_t PLAINTEXT[] = { 0x03 };
    const uint8_t CIPHERTEXT[] = { 0x5e };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-60", "[CFB8][MCT][128][ENCRYPT][n60]") {
    const uint8_t KEY[] = { 0x68,0xbd,0xfd,0x0d,0xe2,0xe9,0xf4,0xfe,0x23,0xb8,0xdb,0x9f,0x5a,0x3d,0xaf,0xf3 };
    const uint8_t IV[] = { 0xb4,0x7c,0x08,0xd5,0xcc,0x6d,0x29,0xd9,0x6e,0x2c,0x44,0x62,0xf0,0x5d,0xde,0x5e };
    const uint8_t PLAINTEXT[] = { 0x0c };
    const uint8_t CIPHERTEXT[] = { 0x2f };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-61", "[CFB8][MCT][128][ENCRYPT][n61]") {
    const uint8_t KEY[] = { 0x55,0x07,0x8d,0x28,0xa1,0xd4,0xbc,0xc5,0xa6,0x0b,0xd1,0x58,0x17,0x04,0xe9,0xdc };
    const uint8_t IV[] = { 0x3d,0xba,0x70,0x25,0x43,0x3d,0x48,0x3b,0x85,0xb3,0x0a,0xc7,0x4d,0x39,0x46,0x2f };
    const uint8_t PLAINTEXT[] = { 0x44 };
    const uint8_t CIPHERTEXT[] = { 0x66 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-62", "[CFB8][MCT][128][ENCRYPT][n62]") {
    const uint8_t KEY[] = { 0x64,0x0e,0x4b,0x46,0x27,0xc7,0x14,0x80,0x11,0x5a,0xc5,0x3b,0x10,0x30,0x33,0xba };
    const uint8_t IV[] = { 0x31,0x09,0xc6,0x6e,0x86,0x13,0xa8,0x45,0xb7,0x51,0x14,0x63,0x07,0x34,0xda,0x66 };
    const uint8_t PLAINTEXT[] = { 0x14 };
    const uint8_t CIPHERTEXT[] = { 0xec };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-63", "[CFB8][MCT][128][ENCRYPT][n63]") {
    const uint8_t KEY[] = { 0x0c,0xd8,0x98,0x79,0xe8,0xf7,0x37,0x9d,0xd7,0xd7,0xc3,0x70,0x55,0x39,0x5d,0x56 };
    const uint8_t IV[] = { 0x68,0xd6,0xd3,0x3f,0xcf,0x30,0x23,0x1d,0xc6,0x8d,0x06,0x4b,0x45,0x09,0x6e,0xec };
    const uint8_t PLAINTEXT[] = { 0x55 };
    const uint8_t CIPHERTEXT[] = { 0xc8 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-64", "[CFB8][MCT][128][ENCRYPT][n64]") {
    const uint8_t KEY[] = { 0xbf,0x3c,0xf6,0x9b,0xc3,0xbe,0x3c,0xe8,0x97,0x53,0x38,0x52,0x00,0x4d,0xcc,0x9e };
    const uint8_t IV[] = { 0xb3,0xe4,0x6e,0xe2,0x2b,0x49,0x0b,0x75,0x40,0x84,0xfb,0x22,0x55,0x74,0x91,0xc8 };
    const uint8_t PLAINTEXT[] = { 0xb2 };
    const uint8_t CIPHERTEXT[] = { 0x48 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-65", "[CFB8][MCT][128][ENCRYPT][n65]") {
    const uint8_t KEY[] = { 0x3f,0x95,0x5f,0xae,0x9d,0x41,0x18,0x8a,0xaf,0x16,0xf2,0x56,0xaf,0x39,0x81,0xd6 };
    const uint8_t IV[] = { 0x80,0xa9,0xa9,0x35,0x5e,0xff,0x24,0x62,0x38,0x45,0xca,0x04,0xaf,0x74,0x4d,0x48 };
    const uint8_t PLAINTEXT[] = { 0xb4 };
    const uint8_t CIPHERTEXT[] = { 0xbd };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-66", "[CFB8][MCT][128][ENCRYPT][n66]") {
    const uint8_t KEY[] = { 0x76,0x15,0x20,0xff,0x9f,0x4b,0xf9,0xde,0xb0,0x26,0xc7,0x99,0xbd,0xbe,0x62,0x6b };
    const uint8_t IV[] = { 0x49,0x80,0x7f,0x51,0x02,0x0a,0xe1,0x54,0x1f,0x30,0x35,0xcf,0x12,0x87,0xe3,0xbd };
    const uint8_t PLAINTEXT[] = { 0x48 };
    const uint8_t CIPHERTEXT[] = { 0x1f };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-67", "[CFB8][MCT][128][ENCRYPT][n67]") {
    const uint8_t KEY[] = { 0xcb,0x42,0xf8,0x4d,0x32,0x52,0x1f,0xb1,0x30,0x5c,0xdd,0x79,0xb6,0x35,0x86,0x74 };
    const uint8_t IV[] = { 0xbd,0x57,0xd8,0xb2,0xad,0x19,0xe6,0x6f,0x80,0x7a,0x1a,0xe0,0x0b,0x8b,0xe4,0x1f };
    const uint8_t PLAINTEXT[] = { 0x4a };
    const uint8_t CIPHERTEXT[] = { 0x5f };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-68", "[CFB8][MCT][128][ENCRYPT][n68]") {
    const uint8_t KEY[] = { 0x39,0x34,0x73,0x57,0xe2,0x43,0xbc,0x3b,0xb6,0xd4,0xe1,0xb9,0x2f,0x58,0x63,0x2b };
    const uint8_t IV[] = { 0xf2,0x76,0x8b,0x1a,0xd0,0x11,0xa3,0x8a,0x86,0x88,0x3c,0xc0,0x99,0x6d,0xe5,0x5f };
    const uint8_t PLAINTEXT[] = { 0x3e };
    const uint8_t CIPHERTEXT[] = { 0x95 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-69", "[CFB8][MCT][128][ENCRYPT][n69]") {
    const uint8_t KEY[] = { 0xa7,0x61,0x02,0x85,0xae,0x95,0xc7,0xaa,0x89,0xd1,0xeb,0x00,0x97,0x08,0x50,0xbe };
    const uint8_t IV[] = { 0x9e,0x55,0x71,0xd2,0x4c,0xd6,0x7b,0x91,0x3f,0x05,0x0a,0xb9,0xb8,0x50,0x33,0x95 };
    const uint8_t PLAINTEXT[] = { 0x01 };
    const uint8_t CIPHERTEXT[] = { 0xc8 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-70", "[CFB8][MCT][128][ENCRYPT][n70]") {
    const uint8_t KEY[] = { 0xd0,0x4b,0xef,0x0d,0x52,0x4e,0x36,0x7d,0xc5,0xef,0x8f,0x8b,0x10,0xcf,0x78,0x76 };
    const uint8_t IV[] = { 0x77,0x2a,0xed,0x88,0xfc,0xdb,0xf1,0xd7,0x4c,0x3e,0x64,0x8b,0x87,0xc7,0x28,0xc8 };
    const uint8_t PLAINTEXT[] = { 0xf6 };
    const uint8_t CIPHERTEXT[] = { 0x10 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-71", "[CFB8][MCT][128][ENCRYPT][n71]") {
    const uint8_t KEY[] = { 0xf6,0x3b,0xd8,0x03,0xb4,0x53,0x7a,0x44,0x37,0x0a,0x2b,0xb0,0xfc,0x28,0xbd,0x66 };
    const uint8_t IV[] = { 0x26,0x70,0x37,0x0e,0xe6,0x1d,0x4c,0x39,0xf2,0xe5,0xa4,0x3b,0xec,0xe7,0xc5,0x10 };
    const uint8_t PLAINTEXT[] = { 0xd7 };
    const uint8_t CIPHERTEXT[] = { 0x23 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-72", "[CFB8][MCT][128][ENCRYPT][n72]") {
    const uint8_t KEY[] = { 0x4d,0xb0,0x4d,0xf7,0x4a,0xc5,0xc8,0xa5,0x8d,0x8d,0x42,0x5a,0x2a,0x2b,0x97,0x45 };
    const uint8_t IV[] = { 0xbb,0x8b,0x95,0xf4,0xfe,0x96,0xb2,0xe1,0xba,0x87,0x69,0xea,0xd6,0x03,0x2a,0x23 };
    const uint8_t PLAINTEXT[] = { 0x60 };
    const uint8_t CIPHERTEXT[] = { 0x21 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-73", "[CFB8][MCT][128][ENCRYPT][n73]") {
    const uint8_t KEY[] = { 0x54,0x93,0xc6,0xee,0xe9,0xd6,0x42,0x3d,0xd6,0x6b,0xd8,0x87,0x63,0x50,0xe8,0x64 };
    const uint8_t IV[] = { 0x19,0x23,0x8b,0x19,0xa3,0x13,0x8a,0x98,0x5b,0xe6,0x9a,0xdd,0x49,0x7b,0x7f,0x21 };
    const uint8_t PLAINTEXT[] = { 0x12 };
    const uint8_t CIPHERTEXT[] = { 0x2b };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-74", "[CFB8][MCT][128][ENCRYPT][n74]") {
    const uint8_t KEY[] = { 0xc3,0xde,0x39,0x52,0x2c,0xf4,0xc3,0xf0,0x3d,0xd2,0xa8,0xfd,0x5d,0xc2,0x0e,0x4f };
    const uint8_t IV[] = { 0x97,0x4d,0xff,0xbc,0xc5,0x22,0x81,0xcd,0xeb,0xb9,0x70,0x7a,0x3e,0x92,0xe6,0x2b };
    const uint8_t PLAINTEXT[] = { 0xfb };
    const uint8_t CIPHERTEXT[] = { 0xb0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-75", "[CFB8][MCT][128][ENCRYPT][n75]") {
    const uint8_t KEY[] = { 0xa1,0x4b,0x0a,0xbb,0x36,0xc4,0x77,0xf0,0xcc,0xc1,0xb8,0x56,0x52,0xc0,0xac,0xff };
    const uint8_t IV[] = { 0x62,0x95,0x33,0xe9,0x1a,0x30,0xb4,0x00,0xf1,0x13,0x10,0xab,0x0f,0x02,0xa2,0xb0 };
    const uint8_t PLAINTEXT[] = { 0xcf };
    const uint8_t CIPHERTEXT[] = { 0x20 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-76", "[CFB8][MCT][128][ENCRYPT][n76]") {
    const uint8_t KEY[] = { 0x0f,0xc8,0xf2,0xd8,0xeb,0xc7,0x0c,0x6e,0xec,0x03,0x10,0x74,0x51,0x1d,0xa4,0xdf };
    const uint8_t IV[] = { 0xae,0x83,0xf8,0x63,0xdd,0x03,0x7b,0x9e,0x20,0xc2,0xa8,0x22,0x03,0xdd,0x08,0x20 };
    const uint8_t PLAINTEXT[] = { 0x89 };
    const uint8_t CIPHERTEXT[] = { 0x4b };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-77", "[CFB8][MCT][128][ENCRYPT][n77]") {
    const uint8_t KEY[] = { 0x23,0xc1,0xd4,0xf7,0x48,0xe4,0xe3,0xb6,0x0d,0xe9,0x3d,0xd1,0x1b,0x9e,0x8c,0x94 };
    const uint8_t IV[] = { 0x2c,0x09,0x26,0x2f,0xa3,0x23,0xef,0xd8,0xe1,0xea,0x2d,0xa5,0x4a,0x83,0x28,0x4b };
    const uint8_t PLAINTEXT[] = { 0xc4 };
    const uint8_t CIPHERTEXT[] = { 0xf3 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-78", "[CFB8][MCT][128][ENCRYPT][n78]") {
    const uint8_t KEY[] = { 0x46,0xdd,0xcd,0x97,0xde,0x9a,0x97,0x4d,0xe9,0xb5,0x4f,0x57,0x4c,0x29,0xe6,0x67 };
    const uint8_t IV[] = { 0x65,0x1c,0x19,0x60,0x96,0x7e,0x74,0xfb,0xe4,0x5c,0x72,0x86,0x57,0xb7,0x6a,0xf3 };
    const uint8_t PLAINTEXT[] = { 0x3c };
    const uint8_t CIPHERTEXT[] = { 0x68 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-79", "[CFB8][MCT][128][ENCRYPT][n79]") {
    const uint8_t KEY[] = { 0x35,0x66,0xbb,0x5e,0x44,0x79,0x59,0x44,0x54,0x94,0x83,0xea,0x3b,0x52,0x8e,0x0f };
    const uint8_t IV[] = { 0x73,0xbb,0x76,0xc9,0x9a,0xe3,0xce,0x09,0xbd,0x21,0xcc,0xbd,0x77,0x7b,0x68,0x68 };
    const uint8_t PLAINTEXT[] = { 0x08 };
    const uint8_t CIPHERTEXT[] = { 0xe4 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-80", "[CFB8][MCT][128][ENCRYPT][n80]") {
    const uint8_t KEY[] = { 0x79,0xda,0x51,0xad,0xeb,0x26,0xd5,0x03,0x6e,0x11,0xa0,0x3a,0xa9,0x95,0x5c,0xeb };
    const uint8_t IV[] = { 0x4c,0xbc,0xea,0xf3,0xaf,0x5f,0x8c,0x47,0x3a,0x85,0x23,0xd0,0x92,0xc7,0xd2,0xe4 };
    const uint8_t PLAINTEXT[] = { 0x4f };
    const uint8_t CIPHERTEXT[] = { 0x78 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-81", "[CFB8][MCT][128][ENCRYPT][n81]") {
    const uint8_t KEY[] = { 0xc1,0x6c,0x75,0xa9,0xab,0x54,0xb2,0xf2,0x75,0x95,0x81,0xa0,0xc1,0xee,0xa2,0x93 };
    const uint8_t IV[] = { 0xb8,0xb6,0x24,0x04,0x40,0x72,0x67,0xf1,0x1b,0x84,0x21,0x9a,0x68,0x7b,0xfe,0x78 };
    const uint8_t PLAINTEXT[] = { 0x0a };
    const uint8_t CIPHERTEXT[] = { 0xc5 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-82", "[CFB8][MCT][128][ENCRYPT][n82]") {
    const uint8_t KEY[] = { 0x3e,0x2b,0xb8,0x2a,0xe1,0xa8,0x3d,0xa5,0x5c,0x5f,0x05,0xad,0x9a,0x46,0xdf,0x56 };
    const uint8_t IV[] = { 0xff,0x47,0xcd,0x83,0x4a,0xfc,0x8f,0x57,0x29,0xca,0x84,0x0d,0x5b,0xa8,0x7d,0xc5 };
    const uint8_t PLAINTEXT[] = { 0x53 };
    const uint8_t CIPHERTEXT[] = { 0x2f };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-83", "[CFB8][MCT][128][ENCRYPT][n83]") {
    const uint8_t KEY[] = { 0x66,0x25,0x49,0xb1,0xeb,0xa4,0x96,0xce,0x49,0x51,0x65,0x7e,0x12,0x0e,0x97,0x79 };
    const uint8_t IV[] = { 0x58,0x0e,0xf1,0x9b,0x0a,0x0c,0xab,0x6b,0x15,0x0e,0x60,0xd3,0x88,0x48,0x48,0x2f };
    const uint8_t PLAINTEXT[] = { 0x81 };
    const uint8_t CIPHERTEXT[] = { 0xb5 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-84", "[CFB8][MCT][128][ENCRYPT][n84]") {
    const uint8_t KEY[] = { 0xc1,0x8a,0x7f,0x45,0x1f,0x6a,0x45,0x56,0xd4,0x8d,0xff,0x72,0xe9,0x36,0x01,0xcc };
    const uint8_t IV[] = { 0xa7,0xaf,0x36,0xf4,0xf4,0xce,0xd3,0x98,0x9d,0xdc,0x9a,0x0c,0xfb,0x38,0x96,0xb5 };
    const uint8_t PLAINTEXT[] = { 0xd3 };
    const uint8_t CIPHERTEXT[] = { 0x64 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-85", "[CFB8][MCT][128][ENCRYPT][n85]") {
    const uint8_t KEY[] = { 0x7e,0xe3,0x35,0x1e,0xe7,0x00,0x04,0x2c,0x3c,0x9e,0x53,0xa6,0xcf,0xf0,0xe0,0xa8 };
    const uint8_t IV[] = { 0xbf,0x69,0x4a,0x5b,0xf8,0x6a,0x41,0x7a,0xe8,0x13,0xac,0xd4,0x26,0xc6,0xe1,0x64 };
    const uint8_t PLAINTEXT[] = { 0xfa };
    const uint8_t CIPHERTEXT[] = { 0xae };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-86", "[CFB8][MCT][128][ENCRYPT][n86]") {
    const uint8_t KEY[] = { 0x59,0x61,0x15,0x83,0x7e,0x2c,0xe7,0x2b,0x50,0xfd,0x15,0xf6,0x0c,0x0a,0x12,0x06 };
    const uint8_t IV[] = { 0x27,0x82,0x20,0x9d,0x99,0x2c,0xe3,0x07,0x6c,0x63,0x46,0x50,0xc3,0xfa,0xf2,0xae };
    const uint8_t PLAINTEXT[] = { 0xf0 };
    const uint8_t CIPHERTEXT[] = { 0x25 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-87", "[CFB8][MCT][128][ENCRYPT][n87]") {
    const uint8_t KEY[] = { 0x37,0xc0,0xca,0x5b,0x57,0xd7,0xba,0xee,0x27,0x88,0x19,0xcd,0x43,0x6b,0x68,0x23 };
    const uint8_t IV[] = { 0x6e,0xa1,0xdf,0xd8,0x29,0xfb,0x5d,0xc5,0x77,0x75,0x0c,0x3b,0x4f,0x61,0x7a,0x25 };
    const uint8_t PLAINTEXT[] = { 0xe7 };
    const uint8_t CIPHERTEXT[] = { 0x6c };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-88", "[CFB8][MCT][128][ENCRYPT][n88]") {
    const uint8_t KEY[] = { 0x46,0xd7,0x3e,0xfb,0x27,0xcd,0xc4,0xfa,0x26,0x25,0x80,0x75,0x14,0x97,0x32,0x4f };
    const uint8_t IV[] = { 0x71,0x17,0xf4,0xa0,0x70,0x1a,0x7e,0x14,0x01,0xad,0x99,0xb8,0x57,0xfc,0x5a,0x6c };
    const uint8_t PLAINTEXT[] = { 0x77 };
    const uint8_t CIPHERTEXT[] = { 0x6a };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-89", "[CFB8][MCT][128][ENCRYPT][n89]") {
    const uint8_t KEY[] = { 0x8d,0xee,0x7c,0xe9,0x63,0x5c,0x40,0x5e,0x0f,0xba,0xcc,0x34,0xf5,0xa3,0x54,0x25 };
    const uint8_t IV[] = { 0xcb,0x39,0x42,0x12,0x44,0x91,0x84,0xa4,0x29,0x9f,0x4c,0x41,0xe1,0x34,0x66,0x6a };
    const uint8_t PLAINTEXT[] = { 0x5b };
    const uint8_t CIPHERTEXT[] = { 0x63 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-90", "[CFB8][MCT][128][ENCRYPT][n90]") {
    const uint8_t KEY[] = { 0xa7,0x6e,0x1b,0x60,0xd9,0xaa,0xb4,0x59,0x81,0xa9,0x68,0xb3,0x07,0xd7,0x95,0x46 };
    const uint8_t IV[] = { 0x2a,0x80,0x67,0x89,0xba,0xf6,0xf4,0x07,0x8e,0x13,0xa4,0x87,0xf2,0x74,0xc1,0x63 };
    const uint8_t PLAINTEXT[] = { 0xbe };
    const uint8_t CIPHERTEXT[] = { 0x63 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-91", "[CFB8][MCT][128][ENCRYPT][n91]") {
    const uint8_t KEY[] = { 0xfa,0xaf,0x35,0xf2,0x92,0x35,0x64,0x55,0x76,0xe6,0x51,0x2e,0xc6,0x3d,0x3e,0x25 };
    const uint8_t IV[] = { 0x5d,0xc1,0x2e,0x92,0x4b,0x9f,0xd0,0x0c,0xf7,0x4f,0x39,0x9d,0xc1,0xea,0xab,0x63 };
    const uint8_t PLAINTEXT[] = { 0xde };
    const uint8_t CIPHERTEXT[] = { 0x32 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-92", "[CFB8][MCT][128][ENCRYPT][n92]") {
    const uint8_t KEY[] = { 0x03,0x62,0x59,0xf2,0xd0,0x89,0xa1,0xc9,0xf5,0x66,0x79,0x7e,0x3d,0x30,0x26,0x17 };
    const uint8_t IV[] = { 0xf9,0xcd,0x6c,0x00,0x42,0xbc,0xc5,0x9c,0x83,0x80,0x28,0x50,0xfb,0x0d,0x18,0x32 };
    const uint8_t PLAINTEXT[] = { 0xf3 };
    const uint8_t CIPHERTEXT[] = { 0x78 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-93", "[CFB8][MCT][128][ENCRYPT][n93]") {
    const uint8_t KEY[] = { 0x3e,0x5c,0xce,0xdc,0x06,0xea,0xd4,0xd6,0xca,0x34,0xb9,0xa3,0x50,0x8d,0xfa,0x6f };
    const uint8_t IV[] = { 0x3d,0x3e,0x97,0x2e,0xd6,0x63,0x75,0x1f,0x3f,0x52,0xc0,0xdd,0x6d,0xbd,0xdc,0x78 };
    const uint8_t PLAINTEXT[] = { 0xe5 };
    const uint8_t CIPHERTEXT[] = { 0x50 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-94", "[CFB8][MCT][128][ENCRYPT][n94]") {
    const uint8_t KEY[] = { 0x3b,0xf3,0x16,0xaa,0x95,0xfb,0xa1,0x0c,0xf1,0x53,0xe4,0x90,0xdc,0x2a,0xec,0x3f };
    const uint8_t IV[] = { 0x05,0xaf,0xd8,0x76,0x93,0x11,0x75,0xda,0x3b,0x67,0x5d,0x33,0x8c,0xa7,0x16,0x50 };
    const uint8_t PLAINTEXT[] = { 0x24 };
    const uint8_t CIPHERTEXT[] = { 0x24 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-95", "[CFB8][MCT][128][ENCRYPT][n95]") {
    const uint8_t KEY[] = { 0x79,0xa4,0x05,0xd4,0x7b,0x3e,0x7d,0x23,0x30,0xb2,0x4c,0x90,0x11,0xf3,0x2a,0x1b };
    const uint8_t IV[] = { 0x42,0x57,0x13,0x7e,0xee,0xc5,0xdc,0x2f,0xc1,0xe1,0xa8,0x00,0xcd,0xd9,0xc6,0x24 };
    const uint8_t PLAINTEXT[] = { 0x61 };
    const uint8_t CIPHERTEXT[] = { 0x34 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-96", "[CFB8][MCT][128][ENCRYPT][n96]") {
    const uint8_t KEY[] = { 0xae,0xa1,0xe5,0x78,0x41,0x37,0xbc,0xbb,0x2d,0x49,0xf6,0xfe,0xd6,0x69,0x27,0x2f };
    const uint8_t IV[] = { 0xd7,0x05,0xe0,0xac,0x3a,0x09,0xc1,0x98,0x1d,0xfb,0xba,0x6e,0xc7,0x9a,0x0d,0x34 };
    const uint8_t PLAINTEXT[] = { 0x42 };
    const uint8_t CIPHERTEXT[] = { 0xe2 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-97", "[CFB8][MCT][128][ENCRYPT][n97]") {
    const uint8_t KEY[] = { 0x60,0xb8,0xa9,0xa6,0xf9,0x8f,0x12,0x34,0xcb,0x0d,0xa0,0xfe,0x78,0x1f,0x75,0xcd };
    const uint8_t IV[] = { 0xce,0x19,0x4c,0xde,0xb8,0xb8,0xae,0x8f,0xe6,0x44,0x56,0x00,0xae,0x76,0x52,0xe2 };
    const uint8_t PLAINTEXT[] = { 0x07 };
    const uint8_t CIPHERTEXT[] = { 0x26 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-98", "[CFB8][MCT][128][ENCRYPT][n98]") {
    const uint8_t KEY[] = { 0x5f,0x95,0x46,0xaf,0x5f,0xec,0x49,0xb6,0xb2,0x28,0x0a,0x28,0x36,0xb3,0x2d,0xeb };
    const uint8_t IV[] = { 0x3f,0x2d,0xef,0x09,0xa6,0x63,0x5b,0x82,0x79,0x25,0xaa,0xd6,0x4e,0xac,0x58,0x26 };
    const uint8_t PLAINTEXT[] = { 0x70 };
    const uint8_t CIPHERTEXT[] = { 0xc0 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-ENCRYPT-99", "[CFB8][MCT][128][ENCRYPT][n99]") {
    const uint8_t KEY[] = { 0x45,0x57,0xc7,0xbd,0x4f,0x12,0xc4,0x7a,0xcd,0x0b,0x85,0x80,0x09,0x19,0x3f,0x2b };
    const uint8_t IV[] = { 0x1a,0xc2,0x81,0x12,0x10,0xfe,0x8d,0xcc,0x7f,0x23,0x8f,0xa8,0x3f,0xaa,0x12,0xc0 };
    const uint8_t PLAINTEXT[] = { 0xb2 };
    const uint8_t CIPHERTEXT[] = { 0x48 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cfb8(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_encrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-0", "[CFB8][MCT][128][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0x78,0x18,0x0b,0xac,0x8a,0x1c,0x97,0x82,0xd7,0x05,0xa8,0x2c,0x86,0x32,0xb0,0xa0 };
    const uint8_t IV[] = { 0x41,0xc7,0xc9,0x79,0xf3,0xd1,0x84,0xf7,0xaa,0x61,0xfb,0x5c,0x5e,0xd6,0x21,0x9d };
    const uint8_t PLAINTEXT[] = { 0xe2 };
    const uint8_t CIPHERTEXT[] = { 0xc9 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-1", "[CFB8][MCT][128][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0x27,0xde,0xca,0xe0,0xaa,0x5d,0x84,0x35,0x7f,0x3c,0x8c,0x20,0xd9,0xae,0x55,0x42 };
    const uint8_t IV[] = { 0x5f,0xc6,0xc1,0x4c,0x20,0x41,0x13,0xb7,0xa8,0x39,0x24,0x0c,0x5f,0x9c,0xe5,0xe2 };
    const uint8_t PLAINTEXT[] = { 0x48 };
    const uint8_t CIPHERTEXT[] = { 0xfd };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-2", "[CFB8][MCT][128][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0xb7,0xe6,0xd5,0x65,0x1c,0xd1,0x69,0x8a,0xa7,0x82,0x01,0x48,0xed,0x3b,0x28,0x0a };
    const uint8_t IV[] = { 0x90,0x38,0x1f,0x85,0xb6,0x8c,0xed,0xbf,0xd8,0xbe,0x8d,0x68,0x34,0x95,0x7d,0x48 };
    const uint8_t PLAINTEXT[] = { 0xe1 };
    const uint8_t CIPHERTEXT[] = { 0xd2 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-3", "[CFB8][MCT][128][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0xf6,0x87,0x67,0x6b,0x5c,0xa2,0x3a,0x3a,0xdf,0x80,0xdb,0x74,0x30,0x41,0x8e,0xeb };
    const uint8_t IV[] = { 0x41,0x61,0xb2,0x0e,0x40,0x73,0x53,0xb0,0x78,0x02,0xda,0x3c,0xdd,0x7a,0xa6,0xe1 };
    const uint8_t PLAINTEXT[] = { 0x3b };
    const uint8_t CIPHERTEXT[] = { 0xc1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-4", "[CFB8][MCT][128][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0xe4,0x4e,0x35,0x37,0x15,0x90,0x15,0xca,0x8c,0xca,0xf1,0x65,0x25,0x02,0xc8,0xd0 };
    const uint8_t IV[] = { 0x12,0xc9,0x52,0x5c,0x49,0x32,0x2f,0xf0,0x53,0x4a,0x2a,0x11,0x15,0x43,0x46,0x3b };
    const uint8_t PLAINTEXT[] = { 0xd2 };
    const uint8_t CIPHERTEXT[] = { 0x8c };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-5", "[CFB8][MCT][128][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0xd0,0x78,0x59,0x04,0x47,0x72,0xd8,0x8b,0x0a,0xbd,0x21,0x37,0x3b,0x6e,0x62,0x02 };
    const uint8_t IV[] = { 0x34,0x36,0x6c,0x33,0x52,0xe2,0xcd,0x41,0x86,0x77,0xd0,0x52,0x1e,0x6c,0xaa,0xd2 };
    const uint8_t PLAINTEXT[] = { 0x5a };
    const uint8_t CIPHERTEXT[] = { 0xa9 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-6", "[CFB8][MCT][128][DECRYPT][n6]") {
    const uint8_t KEY[] = { 0xde,0x06,0x0f,0x28,0xf2,0x6c,0x61,0xcf,0x97,0x65,0x4c,0x06,0x74,0x45,0x81,0x58 };
    const uint8_t IV[] = { 0x0e,0x7e,0x56,0x2c,0xb5,0x1e,0xb9,0x44,0x9d,0xd8,0x6d,0x31,0x4f,0x2b,0xe3,0x5a };
    const uint8_t PLAINTEXT[] = { 0x4c };
    const uint8_t CIPHERTEXT[] = { 0x1f };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-7", "[CFB8][MCT][128][DECRYPT][n7]") {
    const uint8_t KEY[] = { 0x02,0xf6,0x1e,0x40,0xb9,0xd5,0x1f,0xea,0x88,0x2c,0xab,0xa8,0xb0,0x70,0x55,0x14 };
    const uint8_t IV[] = { 0xdc,0xf0,0x11,0x68,0x4b,0xb9,0x7e,0x25,0x1f,0x49,0xe7,0xae,0xc4,0x35,0xd4,0x4c };
    const uint8_t PLAINTEXT[] = { 0x5e };
    const uint8_t CIPHERTEXT[] = { 0x0a };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-8", "[CFB8][MCT][128][DECRYPT][n8]") {
    const uint8_t KEY[] = { 0xd2,0x0c,0x15,0xc7,0x60,0xc1,0x4a,0x2b,0x2e,0xce,0x44,0x2a,0x7e,0x7b,0xc3,0x4a };
    const uint8_t IV[] = { 0xd0,0xfa,0x0b,0x87,0xd9,0x14,0x55,0xc1,0xa6,0xe2,0xef,0x82,0xce,0x0b,0x96,0x5e };
    const uint8_t PLAINTEXT[] = { 0x72 };
    const uint8_t CIPHERTEXT[] = { 0xbb };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-9", "[CFB8][MCT][128][DECRYPT][n9]") {
    const uint8_t KEY[] = { 0xb2,0xf4,0x25,0x5d,0x77,0x51,0x34,0x3f,0x86,0xec,0xc5,0x36,0xb4,0x55,0xdb,0x38 };
    const uint8_t IV[] = { 0x60,0xf8,0x30,0x9a,0x17,0x90,0x7e,0x14,0xa8,0x22,0x81,0x1c,0xca,0x2e,0x18,0x72 };
    const uint8_t PLAINTEXT[] = { 0xbc };
    const uint8_t CIPHERTEXT[] = { 0x9c };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-10", "[CFB8][MCT][128][DECRYPT][n10]") {
    const uint8_t KEY[] = { 0x5d,0x76,0x8c,0xb3,0x3a,0x6a,0x6c,0x42,0x5e,0x45,0x91,0xb1,0x30,0x00,0xc8,0x84 };
    const uint8_t IV[] = { 0xef,0x82,0xa9,0xee,0x4d,0x3b,0x58,0x7d,0xd8,0xa9,0x54,0x87,0x84,0x55,0x13,0xbc };
    const uint8_t PLAINTEXT[] = { 0xce };
    const uint8_t CIPHERTEXT[] = { 0x63 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-11", "[CFB8][MCT][128][DECRYPT][n11]") {
    const uint8_t KEY[] = { 0xa2,0x8a,0xcf,0xde,0x1e,0xb8,0xb7,0xb7,0x57,0x16,0x92,0x42,0x8a,0x71,0x7e,0x4a };
    const uint8_t IV[] = { 0xff,0xfc,0x43,0x6d,0x24,0xd2,0xdb,0xf5,0x09,0x53,0x03,0xf3,0xba,0x71,0xb6,0xce };
    const uint8_t PLAINTEXT[] = { 0xa9 };
    const uint8_t CIPHERTEXT[] = { 0x0d };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-12", "[CFB8][MCT][128][DECRYPT][n12]") {
    const uint8_t KEY[] = { 0x56,0xd1,0xaa,0x8a,0x42,0xcf,0xbf,0xc2,0x6a,0x0d,0xc2,0x98,0xc7,0xef,0x31,0xe3 };
    const uint8_t IV[] = { 0xf4,0x5b,0x65,0x54,0x5c,0x77,0x08,0x75,0x3d,0x1b,0x50,0xda,0x4d,0x9e,0x4f,0xa9 };
    const uint8_t PLAINTEXT[] = { 0x93 };
    const uint8_t CIPHERTEXT[] = { 0x5a };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-13", "[CFB8][MCT][128][DECRYPT][n13]") {
    const uint8_t KEY[] = { 0xea,0xf0,0x7f,0x0b,0xa9,0xf2,0xd2,0xd1,0xb3,0x92,0xb5,0x29,0x1b,0x6e,0x9f,0x70 };
    const uint8_t IV[] = { 0xbc,0x21,0xd5,0x81,0xeb,0x3d,0x6d,0x13,0xd9,0x9f,0x77,0xb1,0xdc,0x81,0xae,0x93 };
    const uint8_t PLAINTEXT[] = { 0xdb };
    const uint8_t CIPHERTEXT[] = { 0x37 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-14", "[CFB8][MCT][128][DECRYPT][n14]") {
    const uint8_t KEY[] = { 0x06,0x08,0x93,0xb0,0x93,0xf5,0xbc,0x2c,0x52,0xa2,0x8a,0x19,0xf5,0xce,0x28,0xab };
    const uint8_t IV[] = { 0xec,0xf8,0xec,0xbb,0x3a,0x07,0x6e,0xfd,0xe1,0x30,0x3f,0x30,0xee,0xa0,0xb7,0xdb };
    const uint8_t PLAINTEXT[] = { 0x90 };
    const uint8_t CIPHERTEXT[] = { 0xad };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-15", "[CFB8][MCT][128][DECRYPT][n15]") {
    const uint8_t KEY[] = { 0x62,0x6a,0xdc,0x62,0xef,0x21,0x83,0xdf,0xdd,0xa5,0x04,0x16,0xa3,0x6c,0x9b,0x3b };
    const uint8_t IV[] = { 0x64,0x62,0x4f,0xd2,0x7c,0xd4,0x3f,0xf3,0x8f,0x07,0x8e,0x0f,0x56,0xa2,0xb3,0x90 };
    const uint8_t PLAINTEXT[] = { 0x60 };
    const uint8_t CIPHERTEXT[] = { 0x32 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-16", "[CFB8][MCT][128][DECRYPT][n16]") {
    const uint8_t KEY[] = { 0x3c,0x24,0x47,0x9c,0x33,0x41,0x07,0xd2,0xa8,0x41,0xfe,0xb5,0x79,0xf2,0xcb,0x5b };
    const uint8_t IV[] = { 0x5e,0x4e,0x9b,0xfe,0xdc,0x60,0x84,0x0d,0x75,0xe4,0xfa,0xa3,0xda,0x9e,0x50,0x60 };
    const uint8_t PLAINTEXT[] = { 0x06 };
    const uint8_t CIPHERTEXT[] = { 0x91 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-17", "[CFB8][MCT][128][DECRYPT][n17]") {
    const uint8_t KEY[] = { 0xe9,0x38,0x35,0x48,0x82,0x06,0x2e,0xe8,0x20,0x76,0x18,0x23,0x32,0xe0,0xc5,0x5d };
    const uint8_t IV[] = { 0xd5,0x1c,0x72,0xd4,0xb1,0x47,0x29,0x3a,0x88,0x37,0xe6,0x96,0x4b,0x12,0x0e,0x06 };
    const uint8_t PLAINTEXT[] = { 0x18 };
    const uint8_t CIPHERTEXT[] = { 0xd1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-18", "[CFB8][MCT][128][DECRYPT][n18]") {
    const uint8_t KEY[] = { 0x62,0xbe,0x0a,0xdc,0xb0,0xef,0x39,0x5f,0x1b,0xe1,0x15,0x36,0xaf,0xdc,0x44,0x45 };
    const uint8_t IV[] = { 0x8b,0x86,0x3f,0x94,0x32,0xe9,0x17,0xb7,0x3b,0x97,0x0d,0x15,0x9d,0x3c,0x81,0x18 };
    const uint8_t PLAINTEXT[] = { 0x45 };
    const uint8_t CIPHERTEXT[] = { 0x2a };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-19", "[CFB8][MCT][128][DECRYPT][n19]") {
    const uint8_t KEY[] = { 0x2b,0x78,0x22,0x66,0x93,0xd8,0xbc,0xde,0xa0,0x04,0x93,0x02,0x29,0x41,0xb8,0x00 };
    const uint8_t IV[] = { 0x49,0xc6,0x28,0xba,0x23,0x37,0x85,0x81,0xbb,0xe5,0x86,0x34,0x86,0x9d,0xfc,0x45 };
    const uint8_t PLAINTEXT[] = { 0x87 };
    const uint8_t CIPHERTEXT[] = { 0xe3 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-20", "[CFB8][MCT][128][DECRYPT][n20]") {
    const uint8_t KEY[] = { 0x23,0x10,0x9f,0x58,0xa0,0xa1,0xc8,0xac,0x4a,0x68,0x22,0xd3,0x15,0x8d,0x19,0x87 };
    const uint8_t IV[] = { 0x08,0x68,0xbd,0x3e,0x33,0x79,0x74,0x72,0xea,0x6c,0xb1,0xd1,0x3c,0xcc,0xa1,0x87 };
    const uint8_t PLAINTEXT[] = { 0xaf };
    const uint8_t CIPHERTEXT[] = { 0xdf };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-21", "[CFB8][MCT][128][DECRYPT][n21]") {
    const uint8_t KEY[] = { 0x79,0x5f,0x7d,0xb0,0x7f,0x5d,0x06,0x20,0xa8,0x7c,0x80,0xa8,0xf0,0x85,0xc4,0x28 };
    const uint8_t IV[] = { 0x5a,0x4f,0xe2,0xe8,0xdf,0xfc,0xce,0x8c,0xe2,0x14,0xa2,0x7b,0xe5,0x08,0xdd,0xaf };
    const uint8_t PLAINTEXT[] = { 0xff };
    const uint8_t CIPHERTEXT[] = { 0x12 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-22", "[CFB8][MCT][128][DECRYPT][n22]") {
    const uint8_t KEY[] = { 0xf3,0xcc,0x40,0x9c,0xfe,0x8c,0x9d,0x6a,0x4d,0x2a,0xae,0x89,0x3e,0x9c,0x84,0xd7 };
    const uint8_t IV[] = { 0x8a,0x93,0x3d,0x2c,0x81,0xd1,0x9b,0x4a,0xe5,0x56,0x2e,0x21,0xce,0x19,0x40,0xff };
    const uint8_t PLAINTEXT[] = { 0xdf };
    const uint8_t CIPHERTEXT[] = { 0x3d };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-23", "[CFB8][MCT][128][DECRYPT][n23]") {
    const uint8_t KEY[] = { 0x63,0x0b,0xd0,0x34,0x73,0x9d,0x63,0xf5,0x82,0x6f,0x0e,0x4f,0x40,0x02,0x07,0x08 };
    const uint8_t IV[] = { 0x90,0xc7,0x90,0xa8,0x8d,0x11,0xfe,0x9f,0xcf,0x45,0xa0,0xc6,0x7e,0x9e,0x83,0xdf };
    const uint8_t PLAINTEXT[] = { 0x98 };
    const uint8_t CIPHERTEXT[] = { 0x89 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-24", "[CFB8][MCT][128][DECRYPT][n24]") {
    const uint8_t KEY[] = { 0x4e,0xa2,0x18,0xa6,0xb6,0xce,0x28,0x41,0x81,0x31,0xef,0x88,0x79,0x9c,0xd3,0x90 };
    const uint8_t IV[] = { 0x2d,0xa9,0xc8,0x92,0xc5,0x53,0x4b,0xb4,0x03,0x5e,0xe1,0xc7,0x39,0x9e,0xd4,0x98 };
    const uint8_t PLAINTEXT[] = { 0x81 };
    const uint8_t CIPHERTEXT[] = { 0xe0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-25", "[CFB8][MCT][128][DECRYPT][n25]") {
    const uint8_t KEY[] = { 0x93,0x55,0x6e,0xb0,0x7e,0xd7,0xd6,0xce,0x0e,0x0e,0x2d,0x52,0x91,0xe3,0x2f,0x11 };
    const uint8_t IV[] = { 0xdd,0xf7,0x76,0x16,0xc8,0x19,0xfe,0x8f,0x8f,0x3f,0xc2,0xda,0xe8,0x7f,0xfc,0x81 };
    const uint8_t PLAINTEXT[] = { 0xfa };
    const uint8_t CIPHERTEXT[] = { 0xbe };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-26", "[CFB8][MCT][128][DECRYPT][n26]") {
    const uint8_t KEY[] = { 0xd7,0x40,0x84,0x2e,0x08,0x64,0xd5,0x60,0xbb,0x24,0x17,0x48,0x1f,0x79,0x91,0xeb };
    const uint8_t IV[] = { 0x44,0x15,0xea,0x9e,0x76,0xb3,0x03,0xae,0xb5,0x2a,0x3a,0x1a,0x8e,0x9a,0xbe,0xfa };
    const uint8_t PLAINTEXT[] = { 0x4f };
    const uint8_t CIPHERTEXT[] = { 0x1e };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-27", "[CFB8][MCT][128][DECRYPT][n27]") {
    const uint8_t KEY[] = { 0xe0,0xa9,0x2e,0xbc,0x6d,0xe7,0x5b,0x40,0xfa,0x04,0x1a,0xf5,0xce,0x3f,0xb0,0xa4 };
    const uint8_t IV[] = { 0x37,0xe9,0xaa,0x92,0x65,0x83,0x8e,0x20,0x41,0x20,0x0d,0xbd,0xd1,0x46,0x21,0x4f };
    const uint8_t PLAINTEXT[] = { 0x49 };
    const uint8_t CIPHERTEXT[] = { 0x54 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-28", "[CFB8][MCT][128][DECRYPT][n28]") {
    const uint8_t KEY[] = { 0x5b,0x55,0x50,0x97,0xbe,0x7f,0xf2,0x78,0x86,0x1d,0x36,0x39,0x2d,0x22,0x7b,0xed };
    const uint8_t IV[] = { 0xbb,0xfc,0x7e,0x2b,0xd3,0x98,0xa9,0x38,0x7c,0x19,0x2c,0xcc,0xe3,0x1d,0xcb,0x49 };
    const uint8_t PLAINTEXT[] = { 0x74 };
    const uint8_t CIPHERTEXT[] = { 0x2d };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-29", "[CFB8][MCT][128][DECRYPT][n29]") {
    const uint8_t KEY[] = { 0x42,0xff,0x9c,0x4e,0xbd,0x4a,0x2a,0x0c,0xbd,0x27,0xce,0xa1,0x53,0x8e,0xd6,0x99 };
    const uint8_t IV[] = { 0x19,0xaa,0xcc,0xd9,0x03,0x35,0xd8,0x74,0x3b,0x3a,0xf8,0x98,0x7e,0xac,0xad,0x74 };
    const uint8_t PLAINTEXT[] = { 0xa4 };
    const uint8_t CIPHERTEXT[] = { 0xcb };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-30", "[CFB8][MCT][128][DECRYPT][n30]") {
    const uint8_t KEY[] = { 0x1a,0x5c,0xcd,0xb8,0x1c,0x9a,0xfd,0x88,0x39,0x54,0x05,0xa3,0x97,0xdf,0x22,0x3d };
    const uint8_t IV[] = { 0x58,0xa3,0x51,0xf6,0xa1,0xd0,0xd7,0x84,0x84,0x73,0xcb,0x02,0xc4,0x51,0xf4,0xa4 };
    const uint8_t PLAINTEXT[] = { 0x71 };
    const uint8_t CIPHERTEXT[] = { 0x9b };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-31", "[CFB8][MCT][128][DECRYPT][n31]") {
    const uint8_t KEY[] = { 0x76,0x6b,0x9c,0x5d,0x86,0xe2,0x4e,0x09,0x5c,0xe9,0xce,0x9a,0x46,0x0b,0xa1,0x4c };
    const uint8_t IV[] = { 0x6c,0x37,0x51,0xe5,0x9a,0x78,0xb3,0x81,0x65,0xbd,0xcb,0x39,0xd1,0xd4,0x83,0x71 };
    const uint8_t PLAINTEXT[] = { 0x22 };
    const uint8_t CIPHERTEXT[] = { 0x03 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-32", "[CFB8][MCT][128][DECRYPT][n32]") {
    const uint8_t KEY[] = { 0x00,0xf7,0x0e,0x61,0x90,0x2e,0x53,0x30,0x6b,0xd3,0x5f,0x25,0x66,0xba,0x2b,0x6e };
    const uint8_t IV[] = { 0x76,0x9c,0x92,0x3c,0x16,0xcc,0x1d,0x39,0x37,0x3a,0x91,0xbf,0x20,0xb1,0x8a,0x22 };
    const uint8_t PLAINTEXT[] = { 0x22 };
    const uint8_t CIPHERTEXT[] = { 0x1e };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-33", "[CFB8][MCT][128][DECRYPT][n33]") {
    const uint8_t KEY[] = { 0x9d,0x47,0xaf,0x7c,0x75,0x9b,0x6b,0xd6,0x10,0x7d,0x87,0xb2,0xef,0x03,0xb6,0x4c };
    const uint8_t IV[] = { 0x9d,0xb0,0xa1,0x1d,0xe5,0xb5,0x38,0xe6,0x7b,0xae,0xd8,0x97,0x89,0xb9,0x9d,0x22 };
    const uint8_t PLAINTEXT[] = { 0x92 };
    const uint8_t CIPHERTEXT[] = { 0x14 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-34", "[CFB8][MCT][128][DECRYPT][n34]") {
    const uint8_t KEY[] = { 0xaa,0x0c,0x2d,0xb6,0xeb,0x7d,0x4a,0xd2,0x92,0x83,0xa8,0xcf,0x86,0xf8,0x8a,0xde };
    const uint8_t IV[] = { 0x37,0x4b,0x82,0xca,0x9e,0xe6,0x21,0x04,0x82,0xfe,0x2f,0x7d,0x69,0xfb,0x3c,0x92 };
    const uint8_t PLAINTEXT[] = { 0xab };
    const uint8_t CIPHERTEXT[] = { 0x06 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-35", "[CFB8][MCT][128][DECRYPT][n35]") {
    const uint8_t KEY[] = { 0x43,0xaa,0xaa,0x3d,0x27,0x56,0x93,0x5f,0xee,0x2d,0x1d,0x8c,0x09,0x96,0xee,0x75 };
    const uint8_t IV[] = { 0xe9,0xa6,0x87,0x8b,0xcc,0x2b,0xd9,0x8d,0x7c,0xae,0xb5,0x43,0x8f,0x6e,0x64,0xab };
    const uint8_t PLAINTEXT[] = { 0x8e };
    const uint8_t CIPHERTEXT[] = { 0x6c };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-36", "[CFB8][MCT][128][DECRYPT][n36]") {
    const uint8_t KEY[] = { 0x9e,0xe5,0x0f,0xa1,0xa4,0x09,0x39,0x8a,0xeb,0x1d,0xd4,0x9e,0x41,0x97,0xa1,0xfb };
    const uint8_t IV[] = { 0xdd,0x4f,0xa5,0x9c,0x83,0x5f,0xaa,0xd5,0x05,0x30,0xc9,0x12,0x48,0x01,0x4f,0x8e };
    const uint8_t PLAINTEXT[] = { 0xef };
    const uint8_t CIPHERTEXT[] = { 0x31 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-37", "[CFB8][MCT][128][DECRYPT][n37]") {
    const uint8_t KEY[] = { 0x22,0x6c,0x1b,0xc3,0x24,0xe1,0x73,0x3e,0xf9,0x1f,0xb1,0x4c,0x89,0xa1,0xe2,0x14 };
    const uint8_t IV[] = { 0xbc,0x89,0x14,0x62,0x80,0xe8,0x4a,0xb4,0x12,0x02,0x65,0xd2,0xc8,0x36,0x43,0xef };
    const uint8_t PLAINTEXT[] = { 0xd2 };
    const uint8_t CIPHERTEXT[] = { 0x22 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-38", "[CFB8][MCT][128][DECRYPT][n38]") {
    const uint8_t KEY[] = { 0xe0,0x27,0x78,0x68,0x6f,0x6a,0x35,0xd8,0x17,0xf5,0x7c,0xf4,0x34,0xfd,0xd6,0xc6 };
    const uint8_t IV[] = { 0xc2,0x4b,0x63,0xab,0x4b,0x8b,0x46,0xe6,0xee,0xea,0xcd,0xb8,0xbd,0x5c,0x34,0xd2 };
    const uint8_t PLAINTEXT[] = { 0xb2 };
    const uint8_t CIPHERTEXT[] = { 0x35 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-39", "[CFB8][MCT][128][DECRYPT][n39]") {
    const uint8_t KEY[] = { 0xaa,0x21,0xca,0x18,0x95,0x47,0x04,0x45,0x7a,0x36,0x43,0x9e,0x15,0x38,0xd6,0x74 };
    const uint8_t IV[] = { 0x4a,0x06,0xb2,0x70,0xfa,0x2d,0x31,0x9d,0x6d,0xc3,0x3f,0x6a,0x21,0xc5,0x00,0xb2 };
    const uint8_t PLAINTEXT[] = { 0xd1 };
    const uint8_t CIPHERTEXT[] = { 0x48 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-40", "[CFB8][MCT][128][DECRYPT][n40]") {
    const uint8_t KEY[] = { 0xdb,0x16,0xaf,0xc8,0xdf,0x99,0x59,0x25,0xca,0x14,0xdf,0xbf,0x3a,0x52,0x22,0xa5 };
    const uint8_t IV[] = { 0x71,0x37,0x65,0xd0,0x4a,0xde,0x5d,0x60,0xb0,0x22,0x9c,0x21,0x2f,0x6a,0xf4,0xd1 };
    const uint8_t PLAINTEXT[] = { 0x75 };
    const uint8_t CIPHERTEXT[] = { 0x0b };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-41", "[CFB8][MCT][128][DECRYPT][n41]") {
    const uint8_t KEY[] = { 0x2a,0x2a,0xb2,0xee,0xae,0x9e,0x6a,0xfc,0x5f,0x94,0x52,0x33,0x89,0x70,0x9c,0xd0 };
    const uint8_t IV[] = { 0xf1,0x3c,0x1d,0x26,0x71,0x07,0x33,0xd9,0x95,0x80,0x8d,0x8c,0xb3,0x22,0xbe,0x75 };
    const uint8_t PLAINTEXT[] = { 0x40 };
    const uint8_t CIPHERTEXT[] = { 0x66 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-42", "[CFB8][MCT][128][DECRYPT][n42]") {
    const uint8_t KEY[] = { 0xc4,0xca,0xed,0xa7,0xd5,0x84,0x65,0xd5,0x26,0x6f,0x1e,0x1e,0x74,0xa8,0x8b,0x90 };
    const uint8_t IV[] = { 0xee,0xe0,0x5f,0x49,0x7b,0x1a,0x0f,0x29,0x79,0xfb,0x4c,0x2d,0xfd,0xd8,0x17,0x40 };
    const uint8_t PLAINTEXT[] = { 0x0a };
    const uint8_t CIPHERTEXT[] = { 0x40 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-43", "[CFB8][MCT][128][DECRYPT][n43]") {
    const uint8_t KEY[] = { 0x1f,0xce,0xbc,0x88,0x55,0xf4,0x5b,0xdf,0x2a,0x03,0x52,0x38,0x43,0x05,0x0e,0x9a };
    const uint8_t IV[] = { 0xdb,0x04,0x51,0x2f,0x80,0x70,0x3e,0x0a,0x0c,0x6c,0x4c,0x26,0x37,0xad,0x85,0x0a };
    const uint8_t PLAINTEXT[] = { 0xb2 };
    const uint8_t CIPHERTEXT[] = { 0x45 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-44", "[CFB8][MCT][128][DECRYPT][n44]") {
    const uint8_t KEY[] = { 0x13,0x71,0x65,0xa2,0x73,0x37,0xc8,0x14,0x15,0x6f,0x9d,0x8f,0xbf,0x4a,0xba,0x28 };
    const uint8_t IV[] = { 0x0c,0xbf,0xd9,0x2a,0x26,0xc3,0x93,0xcb,0x3f,0x6c,0xcf,0xb7,0xfc,0x4f,0xb4,0xb2 };
    const uint8_t PLAINTEXT[] = { 0x40 };
    const uint8_t CIPHERTEXT[] = { 0x80 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-45", "[CFB8][MCT][128][DECRYPT][n45]") {
    const uint8_t KEY[] = { 0x1f,0x15,0x04,0x0a,0x99,0xd4,0xb9,0x28,0x73,0xb5,0x65,0xe4,0xe4,0x9f,0xf9,0x68 };
    const uint8_t IV[] = { 0x0c,0x64,0x61,0xa8,0xea,0xe3,0x71,0x3c,0x66,0xda,0xf8,0x6b,0x5b,0xd5,0x43,0x40 };
    const uint8_t PLAINTEXT[] = { 0x88 };
    const uint8_t CIPHERTEXT[] = { 0x10 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-46", "[CFB8][MCT][128][DECRYPT][n46]") {
    const uint8_t KEY[] = { 0xdc,0x8a,0xcf,0x79,0x9c,0x18,0xfc,0x8c,0x39,0xc7,0x92,0xc2,0xbe,0xe3,0xec,0xe0 };
    const uint8_t IV[] = { 0xc3,0x9f,0xcb,0x73,0x05,0xcc,0x45,0xa4,0x4a,0x72,0xf7,0x26,0x5a,0x7c,0x15,0x88 };
    const uint8_t PLAINTEXT[] = { 0x78 };
    const uint8_t CIPHERTEXT[] = { 0xd2 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-47", "[CFB8][MCT][128][DECRYPT][n47]") {
    const uint8_t KEY[] = { 0x17,0xe8,0x17,0xcc,0xc2,0x3c,0xf7,0xd8,0xe0,0x65,0xc1,0xb9,0xe7,0x3e,0x03,0x98 };
    const uint8_t IV[] = { 0xcb,0x62,0xd8,0xb5,0x5e,0x24,0x0b,0x54,0xd9,0xa2,0x53,0x7b,0x59,0xdd,0xef,0x78 };
    const uint8_t PLAINTEXT[] = { 0xe7 };
    const uint8_t CIPHERTEXT[] = { 0x21 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-48", "[CFB8][MCT][128][DECRYPT][n48]") {
    const uint8_t KEY[] = { 0xf3,0x99,0x94,0xf3,0x64,0xf7,0xba,0x37,0x5d,0xfb,0xa1,0xb0,0xfa,0x10,0x71,0x7f };
    const uint8_t IV[] = { 0xe4,0x71,0x83,0x3f,0xa6,0xcb,0x4d,0xef,0xbd,0x9e,0x60,0x09,0x1d,0x2e,0x72,0xe7 };
    const uint8_t PLAINTEXT[] = { 0x23 };
    const uint8_t CIPHERTEXT[] = { 0x86 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-49", "[CFB8][MCT][128][DECRYPT][n49]") {
    const uint8_t KEY[] = { 0xbe,0x14,0x18,0x23,0xb3,0x47,0x77,0xd0,0x82,0xce,0xb2,0x76,0x75,0x0a,0x1e,0x5c };
    const uint8_t IV[] = { 0x4d,0x8d,0x8c,0xd0,0xd7,0xb0,0xcd,0xe7,0xdf,0x35,0x13,0xc6,0x8f,0x1a,0x6f,0x23 };
    const uint8_t PLAINTEXT[] = { 0xef };
    const uint8_t CIPHERTEXT[] = { 0x9f };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-50", "[CFB8][MCT][128][DECRYPT][n50]") {
    const uint8_t KEY[] = { 0x8e,0xc5,0xaa,0xbf,0x24,0x42,0x37,0x2b,0xcf,0x52,0xc9,0xe1,0x89,0x01,0xe0,0xb3 };
    const uint8_t IV[] = { 0x30,0xd1,0xb2,0x9c,0x97,0x05,0x40,0xfb,0x4d,0x9c,0x7b,0x97,0xfc,0x0b,0xfe,0xef };
    const uint8_t PLAINTEXT[] = { 0x56 };
    const uint8_t CIPHERTEXT[] = { 0xc3 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-51", "[CFB8][MCT][128][DECRYPT][n51]") {
    const uint8_t KEY[] = { 0xde,0x71,0xea,0xd3,0xc5,0x3b,0xac,0x3b,0xce,0xe1,0x90,0x87,0x1c,0xaa,0xe9,0xe5 };
    const uint8_t IV[] = { 0x50,0xb4,0x40,0x6c,0xe1,0x79,0x9b,0x10,0x01,0xb3,0x59,0x66,0x95,0xab,0x09,0x56 };
    const uint8_t PLAINTEXT[] = { 0xc2 };
    const uint8_t CIPHERTEXT[] = { 0x3a };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-52", "[CFB8][MCT][128][DECRYPT][n52]") {
    const uint8_t KEY[] = { 0x22,0x2c,0xe9,0x67,0x94,0xf7,0x67,0x55,0x22,0x86,0x38,0x2c,0x56,0x85,0x12,0x27 };
    const uint8_t IV[] = { 0xfc,0x5d,0x03,0xb4,0x51,0xcc,0xcb,0x6e,0xec,0x67,0xa8,0xab,0x4a,0x2f,0xfb,0xc2 };
    const uint8_t PLAINTEXT[] = { 0x6b };
    const uint8_t CIPHERTEXT[] = { 0x46 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-53", "[CFB8][MCT][128][DECRYPT][n53]") {
    const uint8_t KEY[] = { 0x6e,0xa7,0x1a,0x43,0x0d,0xb0,0x12,0x77,0xf1,0x5d,0x56,0x2c,0x21,0xc4,0xbb,0x4c };
    const uint8_t IV[] = { 0x4c,0x8b,0xf3,0x24,0x99,0x47,0x75,0x22,0xd3,0xdb,0x6e,0x00,0x77,0x41,0xa9,0x6b };
    const uint8_t PLAINTEXT[] = { 0x45 };
    const uint8_t CIPHERTEXT[] = { 0xce };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-54", "[CFB8][MCT][128][DECRYPT][n54]") {
    const uint8_t KEY[] = { 0x92,0xd4,0xbb,0x1a,0x82,0xb5,0x3c,0x85,0x15,0x36,0x1d,0xf0,0xf2,0x4b,0x6f,0x09 };
    const uint8_t IV[] = { 0xfc,0x73,0xa1,0x59,0x8f,0x05,0x2e,0xf2,0xe4,0x6b,0x4b,0xdc,0xd3,0x8f,0xd4,0x45 };
    const uint8_t PLAINTEXT[] = { 0xe2 };
    const uint8_t CIPHERTEXT[] = { 0xbd };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-55", "[CFB8][MCT][128][DECRYPT][n55]") {
    const uint8_t KEY[] = { 0x97,0xc9,0x42,0x7b,0x35,0x2f,0x1c,0xd2,0x5f,0x5d,0xb9,0xd8,0x67,0x7b,0x41,0xeb };
    const uint8_t IV[] = { 0x05,0x1d,0xf9,0x61,0xb7,0x9a,0x20,0x57,0x4a,0x6b,0xa4,0x28,0x95,0x30,0x2e,0xe2 };
    const uint8_t PLAINTEXT[] = { 0x17 };
    const uint8_t CIPHERTEXT[] = { 0x07 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-56", "[CFB8][MCT][128][DECRYPT][n56]") {
    const uint8_t KEY[] = { 0xc9,0x88,0x80,0x8d,0x84,0x21,0x6d,0x03,0x58,0x51,0x45,0x2c,0x06,0x30,0x26,0xfc };
    const uint8_t IV[] = { 0x5e,0x41,0xc2,0xf6,0xb1,0x0e,0x71,0xd1,0x07,0x0c,0xfc,0xf4,0x61,0x4b,0x67,0x17 };
    const uint8_t PLAINTEXT[] = { 0x10 };
    const uint8_t CIPHERTEXT[] = { 0x8f };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-57", "[CFB8][MCT][128][DECRYPT][n57]") {
    const uint8_t KEY[] = { 0xce,0x1c,0xb0,0x76,0xa5,0x1e,0x97,0x27,0x62,0x29,0xa0,0x27,0x68,0x55,0xa7,0xec };
    const uint8_t IV[] = { 0x07,0x94,0x30,0xfb,0x21,0x3f,0xfa,0x24,0x3a,0x78,0xe5,0x0b,0x6e,0x65,0x81,0x10 };
    const uint8_t PLAINTEXT[] = { 0x60 };
    const uint8_t CIPHERTEXT[] = { 0xac };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-58", "[CFB8][MCT][128][DECRYPT][n58]") {
    const uint8_t KEY[] = { 0x9f,0x82,0x6a,0xe3,0x2b,0xe1,0x28,0xb2,0x46,0x6d,0xed,0x59,0x23,0x03,0xba,0x8c };
    const uint8_t IV[] = { 0x51,0x9e,0xda,0x95,0x8e,0xff,0xbf,0x95,0x24,0x44,0x4d,0x7e,0x4b,0x56,0x1d,0x60 };
    const uint8_t PLAINTEXT[] = { 0x67 };
    const uint8_t CIPHERTEXT[] = { 0x1b };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-59", "[CFB8][MCT][128][DECRYPT][n59]") {
    const uint8_t KEY[] = { 0x18,0x9f,0x66,0x7b,0xa8,0xd8,0xf4,0x1c,0x72,0x3b,0x65,0xcc,0x48,0x1a,0x72,0xeb };
    const uint8_t IV[] = { 0x87,0x1d,0x0c,0x98,0x83,0x39,0xdc,0xae,0x34,0x56,0x88,0x95,0x6b,0x19,0xc8,0x67 };
    const uint8_t PLAINTEXT[] = { 0xb5 };
    const uint8_t CIPHERTEXT[] = { 0x53 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-60", "[CFB8][MCT][128][DECRYPT][n60]") {
    const uint8_t KEY[] = { 0xd4,0x17,0x7a,0x8a,0x45,0x53,0xbb,0x70,0x8d,0xd8,0x2f,0x07,0x7e,0x42,0x1d,0x5e };
    const uint8_t IV[] = { 0xcc,0x88,0x1c,0xf1,0xed,0x8b,0x4f,0x6c,0xff,0xe3,0x4a,0xcb,0x36,0x58,0x6f,0xb5 };
    const uint8_t PLAINTEXT[] = { 0xb6 };
    const uint8_t CIPHERTEXT[] = { 0x62 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-61", "[CFB8][MCT][128][DECRYPT][n61]") {
    const uint8_t KEY[] = { 0x1b,0x87,0xbe,0x4a,0x00,0x1d,0x99,0x17,0xfd,0xc8,0x6b,0x11,0xbb,0x2d,0xf9,0xe8 };
    const uint8_t IV[] = { 0xcf,0x90,0xc4,0xc0,0x45,0x4e,0x22,0x67,0x70,0x10,0x44,0x16,0xc5,0x6f,0xe4,0xb6 };
    const uint8_t PLAINTEXT[] = { 0x46 };
    const uint8_t CIPHERTEXT[] = { 0x69 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-62", "[CFB8][MCT][128][DECRYPT][n62]") {
    const uint8_t KEY[] = { 0x9f,0x77,0xb9,0x87,0x64,0x9b,0x00,0xb6,0x4b,0x06,0xd7,0x8c,0x8a,0xdc,0x43,0xae };
    const uint8_t IV[] = { 0x84,0xf0,0x07,0xcd,0x64,0x86,0x99,0xa1,0xb6,0xce,0xbc,0x9d,0x31,0xf1,0xba,0x46 };
    const uint8_t PLAINTEXT[] = { 0xb0 };
    const uint8_t CIPHERTEXT[] = { 0x84 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-63", "[CFB8][MCT][128][DECRYPT][n63]") {
    const uint8_t KEY[] = { 0x10,0x26,0x8c,0x17,0xeb,0x08,0x28,0xb8,0xe8,0xda,0x98,0xa7,0xd1,0xc7,0xd0,0x1e };
    const uint8_t IV[] = { 0x8f,0x51,0x35,0x90,0x8f,0x93,0x28,0x0e,0xa3,0xdc,0x4f,0x2b,0x5b,0x1b,0x93,0xb0 };
    const uint8_t PLAINTEXT[] = { 0x4c };
    const uint8_t CIPHERTEXT[] = { 0x3f };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-64", "[CFB8][MCT][128][DECRYPT][n64]") {
    const uint8_t KEY[] = { 0x39,0x20,0xfc,0x35,0xc0,0xb4,0x62,0x27,0xf4,0xaf,0x04,0xa0,0xcc,0x7e,0x0f,0x52 };
    const uint8_t IV[] = { 0x29,0x06,0x70,0x22,0x2b,0xbc,0x4a,0x9f,0x1c,0x75,0x9c,0x07,0x1d,0xb9,0xdf,0x4c };
    const uint8_t PLAINTEXT[] = { 0x03 };
    const uint8_t CIPHERTEXT[] = { 0x8a };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-65", "[CFB8][MCT][128][DECRYPT][n65]") {
    const uint8_t KEY[] = { 0x2f,0xd1,0x1d,0xd6,0x4a,0xfc,0x32,0x1e,0x85,0xaa,0x33,0xcf,0x90,0xa4,0x6a,0x51 };
    const uint8_t IV[] = { 0x16,0xf1,0xe1,0xe3,0x8a,0x48,0x50,0x39,0x71,0x05,0x37,0x6f,0x5c,0xda,0x65,0x03 };
    const uint8_t PLAINTEXT[] = { 0x4a };
    const uint8_t CIPHERTEXT[] = { 0x7e };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-66", "[CFB8][MCT][128][DECRYPT][n66]") {
    const uint8_t KEY[] = { 0x39,0x46,0x92,0x5a,0xa1,0xf7,0x67,0x8a,0xf0,0x03,0xca,0x63,0x9d,0xf1,0xb4,0x1b };
    const uint8_t IV[] = { 0x16,0x97,0x8f,0x8c,0xeb,0x0b,0x55,0x94,0x75,0xa9,0xf9,0xac,0x0d,0x55,0xde,0x4a };
    const uint8_t PLAINTEXT[] = { 0x87 };
    const uint8_t CIPHERTEXT[] = { 0xbf };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-67", "[CFB8][MCT][128][DECRYPT][n67]") {
    const uint8_t KEY[] = { 0x70,0x20,0xcc,0xfe,0x72,0x92,0xf9,0x13,0xa7,0x03,0x8f,0xbf,0x3c,0x1a,0x80,0x9c };
    const uint8_t IV[] = { 0x49,0x66,0x5e,0xa4,0xd3,0x65,0x9e,0x99,0x57,0x00,0x45,0xdc,0xa1,0xeb,0x34,0x87 };
    const uint8_t PLAINTEXT[] = { 0x54 };
    const uint8_t CIPHERTEXT[] = { 0x4a };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-68", "[CFB8][MCT][128][DECRYPT][n68]") {
    const uint8_t KEY[] = { 0xa0,0x53,0x05,0x18,0xa2,0x09,0x53,0x88,0x0c,0xb7,0x09,0x67,0xa6,0x04,0x6e,0xc8 };
    const uint8_t IV[] = { 0xd0,0x73,0xc9,0xe6,0xd0,0x9b,0xaa,0x9b,0xab,0xb4,0x86,0xd8,0x9a,0x1e,0xee,0x54 };
    const uint8_t PLAINTEXT[] = { 0x09 };
    const uint8_t CIPHERTEXT[] = { 0x30 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-69", "[CFB8][MCT][128][DECRYPT][n69]") {
    const uint8_t KEY[] = { 0xdf,0xc8,0x05,0x79,0x28,0x52,0xc5,0xdb,0x69,0xbf,0xac,0x24,0xc4,0xa6,0x18,0xc1 };
    const uint8_t IV[] = { 0x7f,0x9b,0x00,0x61,0x8a,0x5b,0x96,0x53,0x65,0x08,0xa5,0x43,0x62,0xa2,0x76,0x09 };
    const uint8_t PLAINTEXT[] = { 0x41 };
    const uint8_t CIPHERTEXT[] = { 0xe1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-70", "[CFB8][MCT][128][DECRYPT][n70]") {
    const uint8_t KEY[] = { 0xd5,0x2f,0xed,0xcf,0x89,0xcb,0x74,0xc1,0x00,0xd1,0xa7,0xbf,0xc6,0x0f,0x1c,0x80 };
    const uint8_t IV[] = { 0x0a,0xe7,0xe8,0xb6,0xa1,0x99,0xb1,0x1a,0x69,0x6e,0x0b,0x9b,0x02,0xa9,0x04,0x41 };
    const uint8_t PLAINTEXT[] = { 0x4c };
    const uint8_t CIPHERTEXT[] = { 0x75 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-71", "[CFB8][MCT][128][DECRYPT][n71]") {
    const uint8_t KEY[] = { 0xa9,0x6b,0x3d,0x3a,0xc6,0x27,0x86,0x5f,0x03,0x8b,0x27,0xfe,0xcd,0x7d,0x2c,0xcc };
    const uint8_t IV[] = { 0x7c,0x44,0xd0,0xf5,0x4f,0xec,0xf2,0x9e,0x03,0x5a,0x80,0x41,0x0b,0x72,0x30,0x4c };
    const uint8_t PLAINTEXT[] = { 0x74 };
    const uint8_t CIPHERTEXT[] = { 0xaf };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-72", "[CFB8][MCT][128][DECRYPT][n72]") {
    const uint8_t KEY[] = { 0x01,0x46,0xbc,0x35,0x4e,0xf0,0xc8,0x5e,0x02,0x3b,0xb2,0xce,0x32,0x79,0xc8,0xb8 };
    const uint8_t IV[] = { 0xa8,0x2d,0x81,0x0f,0x88,0xd7,0x4e,0x01,0x01,0xb0,0x95,0x30,0xff,0x04,0xe4,0x74 };
    const uint8_t PLAINTEXT[] = { 0x76 };
    const uint8_t CIPHERTEXT[] = { 0xec };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-73", "[CFB8][MCT][128][DECRYPT][n73]") {
    const uint8_t KEY[] = { 0xb0,0x35,0x84,0x20,0x97,0x24,0x65,0xcf,0x63,0x7b,0xf8,0x60,0x5e,0x05,0xc8,0xce };
    const uint8_t IV[] = { 0xb1,0x73,0x38,0x15,0xd9,0xd4,0xad,0x91,0x61,0x40,0x4a,0xae,0x6c,0x7c,0x00,0x76 };
    const uint8_t PLAINTEXT[] = { 0xbf };
    const uint8_t CIPHERTEXT[] = { 0x8f };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-74", "[CFB8][MCT][128][DECRYPT][n74]") {
    const uint8_t KEY[] = { 0x8d,0x77,0x87,0x67,0xd0,0x77,0x9c,0x54,0xf2,0x4a,0x42,0xea,0xae,0x28,0xfa,0x71 };
    const uint8_t IV[] = { 0x3d,0x42,0x03,0x47,0x47,0x53,0xf9,0x9b,0x91,0x31,0xba,0x8a,0xf0,0x2d,0x32,0xbf };
    const uint8_t PLAINTEXT[] = { 0xe7 };
    const uint8_t CIPHERTEXT[] = { 0x6f };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-75", "[CFB8][MCT][128][DECRYPT][n75]") {
    const uint8_t KEY[] = { 0xe2,0xfd,0xed,0x25,0x53,0x7c,0x50,0xda,0xd3,0x34,0xad,0xe5,0xf6,0x14,0xe2,0x96 };
    const uint8_t IV[] = { 0x6f,0x8a,0x6a,0x42,0x83,0x0b,0xcc,0x8e,0x21,0x7e,0xef,0x0f,0x58,0x3c,0x18,0xe7 };
    const uint8_t PLAINTEXT[] = { 0x99 };
    const uint8_t CIPHERTEXT[] = { 0x04 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-76", "[CFB8][MCT][128][DECRYPT][n76]") {
    const uint8_t KEY[] = { 0xe5,0x4a,0xd3,0x67,0x0a,0xb1,0xd0,0xd2,0x06,0xc4,0x88,0x95,0xc6,0xe2,0x61,0x0f };
    const uint8_t IV[] = { 0x07,0xb7,0x3e,0x42,0x59,0xcd,0x80,0x08,0xd5,0xf0,0x25,0x70,0x30,0xf6,0x83,0x99 };
    const uint8_t PLAINTEXT[] = { 0x47 };
    const uint8_t CIPHERTEXT[] = { 0xca };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-77", "[CFB8][MCT][128][DECRYPT][n77]") {
    const uint8_t KEY[] = { 0x23,0xd7,0x23,0xe5,0x92,0xa9,0x7b,0xf3,0xcb,0x69,0xe8,0x9a,0x63,0x80,0x2a,0x48 };
    const uint8_t IV[] = { 0xc6,0x9d,0xf0,0x82,0x98,0x18,0xab,0x21,0xcd,0xad,0x60,0x0f,0xa5,0x62,0x4b,0x47 };
    const uint8_t PLAINTEXT[] = { 0xa0 };
    const uint8_t CIPHERTEXT[] = { 0x16 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-78", "[CFB8][MCT][128][DECRYPT][n78]") {
    const uint8_t KEY[] = { 0xb4,0xb8,0x83,0x42,0xe9,0x5e,0x01,0xc8,0x16,0xff,0xe2,0x6f,0xb4,0x47,0xa0,0xe8 };
    const uint8_t IV[] = { 0x97,0x6f,0xa0,0xa7,0x7b,0xf7,0x7a,0x3b,0xdd,0x96,0x0a,0xf5,0xd7,0xc7,0x8a,0xa0 };
    const uint8_t PLAINTEXT[] = { 0xe4 };
    const uint8_t CIPHERTEXT[] = { 0xa5 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-79", "[CFB8][MCT][128][DECRYPT][n79]") {
    const uint8_t KEY[] = { 0x61,0x3d,0xce,0x07,0xc7,0xdf,0x9e,0x4a,0x59,0x05,0xda,0x49,0xf0,0x86,0x14,0x0c };
    const uint8_t IV[] = { 0xd5,0x85,0x4d,0x45,0x2e,0x81,0x9f,0x82,0x4f,0xfa,0x38,0x26,0x44,0xc1,0xb4,0xe4 };
    const uint8_t PLAINTEXT[] = { 0xeb };
    const uint8_t CIPHERTEXT[] = { 0x27 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-80", "[CFB8][MCT][128][DECRYPT][n80]") {
    const uint8_t KEY[] = { 0x4a,0x50,0xb4,0x17,0x3e,0x30,0xd0,0xed,0xa6,0x3e,0x1d,0xbe,0x00,0x37,0xb0,0xe7 };
    const uint8_t IV[] = { 0x2b,0x6d,0x7a,0x10,0xf9,0xef,0x4e,0xa7,0xff,0x3b,0xc7,0xf7,0xf0,0xb1,0xa4,0xeb };
    const uint8_t PLAINTEXT[] = { 0xcd };
    const uint8_t CIPHERTEXT[] = { 0x2d };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-81", "[CFB8][MCT][128][DECRYPT][n81]") {
    const uint8_t KEY[] = { 0x3d,0x1e,0x24,0x7e,0xc6,0x77,0x3b,0xad,0x5b,0xee,0xba,0xf8,0x9a,0x69,0xf9,0x2a };
    const uint8_t IV[] = { 0x77,0x4e,0x90,0x69,0xf8,0x47,0xeb,0x40,0xfd,0xd0,0xa7,0x46,0x9a,0x5e,0x49,0xcd };
    const uint8_t PLAINTEXT[] = { 0xf0 };
    const uint8_t CIPHERTEXT[] = { 0x06 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-82", "[CFB8][MCT][128][DECRYPT][n82]") {
    const uint8_t KEY[] = { 0x5c,0x9d,0xa0,0x75,0xad,0xe9,0x6a,0x55,0x9d,0x63,0xe0,0xf7,0x32,0x16,0x68,0xda };
    const uint8_t IV[] = { 0x61,0x83,0x84,0x0b,0x6b,0x9e,0x51,0xf8,0xc6,0x8d,0x5a,0x0f,0xa8,0x7f,0x91,0xf0 };
    const uint8_t PLAINTEXT[] = { 0xab };
    const uint8_t CIPHERTEXT[] = { 0xcc };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-83", "[CFB8][MCT][128][DECRYPT][n83]") {
    const uint8_t KEY[] = { 0xa2,0xa4,0x1a,0x1c,0xd0,0x39,0x85,0xd1,0x5b,0xb2,0x94,0x13,0xd1,0x09,0xf6,0x71 };
    const uint8_t IV[] = { 0xfe,0x39,0xba,0x69,0x7d,0xd0,0xef,0x84,0xc6,0xd1,0x74,0xe4,0xe3,0x1f,0x9e,0xab };
    const uint8_t PLAINTEXT[] = { 0x4c };
    const uint8_t CIPHERTEXT[] = { 0xce };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-84", "[CFB8][MCT][128][DECRYPT][n84]") {
    const uint8_t KEY[] = { 0x0e,0x95,0x08,0xb9,0x04,0xf1,0x9c,0xa1,0x1b,0x4d,0xd2,0x12,0x5c,0xae,0xae,0x3d };
    const uint8_t IV[] = { 0xac,0x31,0x12,0xa5,0xd4,0xc8,0x19,0x70,0x40,0xff,0x46,0x01,0x8d,0xa7,0x58,0x4c };
    const uint8_t PLAINTEXT[] = { 0xee };
    const uint8_t CIPHERTEXT[] = { 0xc3 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-85", "[CFB8][MCT][128][DECRYPT][n85]") {
    const uint8_t KEY[] = { 0x86,0xdc,0xbb,0xdd,0x82,0xc7,0xc6,0xcf,0x34,0xc2,0xd4,0x42,0x0c,0x4c,0x55,0xd3 };
    const uint8_t IV[] = { 0x88,0x49,0xb3,0x64,0x86,0x36,0x5a,0x6e,0x2f,0x8f,0x06,0x50,0x50,0xe2,0xfb,0xee };
    const uint8_t PLAINTEXT[] = { 0xc6 };
    const uint8_t CIPHERTEXT[] = { 0xad };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-86", "[CFB8][MCT][128][DECRYPT][n86]") {
    const uint8_t KEY[] = { 0xdc,0xe1,0x52,0x8f,0xf1,0x74,0xe9,0x6e,0xcd,0xef,0xd9,0x87,0xdd,0xb6,0xf7,0x15 };
    const uint8_t IV[] = { 0x5a,0x3d,0xe9,0x52,0x73,0xb3,0x2f,0xa1,0xf9,0x2d,0x0d,0xc5,0xd1,0xfa,0xa2,0xc6 };
    const uint8_t PLAINTEXT[] = { 0xb4 };
    const uint8_t CIPHERTEXT[] = { 0xe7 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-87", "[CFB8][MCT][128][DECRYPT][n87]") {
    const uint8_t KEY[] = { 0x3a,0xbd,0x3c,0x3e,0xa8,0xa9,0x75,0x52,0x0d,0x89,0x59,0x19,0xcf,0x02,0xd7,0xa1 };
    const uint8_t IV[] = { 0xe6,0x5c,0x6e,0xb1,0x59,0xdd,0x9c,0x3c,0xc0,0x66,0x80,0x9e,0x12,0xb4,0x20,0xb4 };
    const uint8_t PLAINTEXT[] = { 0x02 };
    const uint8_t CIPHERTEXT[] = { 0xc1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-88", "[CFB8][MCT][128][DECRYPT][n88]") {
    const uint8_t KEY[] = { 0xae,0xd5,0x28,0xbe,0x59,0x88,0x87,0xb4,0x2e,0xac,0x9c,0x55,0x0d,0x75,0xa3,0xa3 };
    const uint8_t IV[] = { 0x94,0x68,0x14,0x80,0xf1,0x21,0xf2,0xe6,0x23,0x25,0xc5,0x4c,0xc2,0x77,0x74,0x02 };
    const uint8_t PLAINTEXT[] = { 0xc7 };
    const uint8_t CIPHERTEXT[] = { 0x2a };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-89", "[CFB8][MCT][128][DECRYPT][n89]") {
    const uint8_t KEY[] = { 0xe3,0xd8,0x5c,0x60,0x38,0xd9,0x48,0xb3,0x88,0x39,0x10,0x0e,0x6e,0xb5,0x71,0x64 };
    const uint8_t IV[] = { 0x4d,0x0d,0x74,0xde,0x61,0x51,0xcf,0x07,0xa6,0x95,0x8c,0x5b,0x63,0xc0,0xd2,0xc7 };
    const uint8_t PLAINTEXT[] = { 0x25 };
    const uint8_t CIPHERTEXT[] = { 0x08 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-90", "[CFB8][MCT][128][DECRYPT][n90]") {
    const uint8_t KEY[] = { 0x76,0xa6,0x5d,0xfd,0x6c,0x30,0xba,0xc0,0x15,0x66,0xf1,0x50,0x40,0x2c,0x6b,0x41 };
    const uint8_t IV[] = { 0x95,0x7e,0x01,0x9d,0x54,0xe9,0xf2,0x73,0x9d,0x5f,0xe1,0x5e,0x2e,0x99,0x1a,0x25 };
    const uint8_t PLAINTEXT[] = { 0x85 };
    const uint8_t CIPHERTEXT[] = { 0xad };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-91", "[CFB8][MCT][128][DECRYPT][n91]") {
    const uint8_t KEY[] = { 0xc7,0x13,0xae,0xbc,0x7d,0xa8,0x04,0x98,0xa1,0xee,0xe5,0xd5,0xf8,0xb9,0x57,0xc4 };
    const uint8_t IV[] = { 0xb1,0xb5,0xf3,0x41,0x11,0x98,0xbe,0x58,0xb4,0x88,0x14,0x85,0xb8,0x95,0x3c,0x85 };
    const uint8_t PLAINTEXT[] = { 0x87 };
    const uint8_t CIPHERTEXT[] = { 0xc4 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-92", "[CFB8][MCT][128][DECRYPT][n92]") {
    const uint8_t KEY[] = { 0xc6,0x07,0x2a,0x61,0x69,0xeb,0x7e,0xbf,0x5a,0x5c,0xaa,0xf0,0x7c,0xc0,0xb9,0x43 };
    const uint8_t IV[] = { 0x01,0x14,0x84,0xdd,0x14,0x43,0x7a,0x27,0xfb,0xb2,0x4f,0x25,0x84,0x79,0xee,0x87 };
    const uint8_t PLAINTEXT[] = { 0x53 };
    const uint8_t CIPHERTEXT[] = { 0x35 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-93", "[CFB8][MCT][128][DECRYPT][n93]") {
    const uint8_t KEY[] = { 0x8c,0x52,0x2c,0x4e,0x9e,0x49,0x45,0xec,0x49,0xa3,0x6c,0x5d,0xab,0xcd,0x5b,0x10 };
    const uint8_t IV[] = { 0x4a,0x55,0x06,0x2f,0xf7,0xa2,0x3b,0x53,0x13,0xff,0xc6,0xad,0xd7,0x0d,0xe2,0x53 };
    const uint8_t PLAINTEXT[] = { 0x47 };
    const uint8_t CIPHERTEXT[] = { 0x69 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-94", "[CFB8][MCT][128][DECRYPT][n94]") {
    const uint8_t KEY[] = { 0x99,0xe5,0xe0,0xe7,0x0d,0xce,0x2c,0xc4,0xe0,0x06,0x2a,0x9c,0x01,0x0a,0xa6,0x57 };
    const uint8_t IV[] = { 0x15,0xb7,0xcc,0xa9,0x93,0x87,0x69,0x28,0xa9,0xa5,0x46,0xc1,0xaa,0xc7,0xfd,0x47 };
    const uint8_t PLAINTEXT[] = { 0xa7 };
    const uint8_t CIPHERTEXT[] = { 0xef };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-95", "[CFB8][MCT][128][DECRYPT][n95]") {
    const uint8_t KEY[] = { 0x7c,0x44,0x5f,0x43,0xb1,0xa2,0x3a,0x90,0xfd,0x73,0xd6,0x90,0x25,0x8c,0x54,0xf0 };
    const uint8_t IV[] = { 0xe5,0xa1,0xbf,0xa4,0xbc,0x6c,0x16,0x54,0x1d,0x75,0xfc,0x0c,0x24,0x86,0xf2,0xa7 };
    const uint8_t PLAINTEXT[] = { 0x28 };
    const uint8_t CIPHERTEXT[] = { 0xdd };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-96", "[CFB8][MCT][128][DECRYPT][n96]") {
    const uint8_t KEY[] = { 0x19,0x57,0xf5,0xa7,0x4d,0x99,0x19,0xfc,0x3b,0xae,0x7d,0xbe,0x74,0xf7,0xc3,0xd8 };
    const uint8_t IV[] = { 0x65,0x13,0xaa,0xe4,0xfc,0x3b,0x23,0x6c,0xc6,0xdd,0xab,0x2e,0x51,0x7b,0x97,0x28 };
    const uint8_t PLAINTEXT[] = { 0x63 };
    const uint8_t CIPHERTEXT[] = { 0x9e };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-97", "[CFB8][MCT][128][DECRYPT][n97]") {
    const uint8_t KEY[] = { 0x45,0xc3,0x59,0x87,0xbc,0x90,0x09,0x78,0xc3,0x90,0x44,0x5b,0x5f,0x4e,0x8c,0xbb };
    const uint8_t IV[] = { 0x5c,0x94,0xac,0x20,0xf1,0x09,0x10,0x84,0xf8,0x3e,0x39,0xe5,0x2b,0xb9,0x4f,0x63 };
    const uint8_t PLAINTEXT[] = { 0x22 };
    const uint8_t CIPHERTEXT[] = { 0xd7 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-98", "[CFB8][MCT][128][DECRYPT][n98]") {
    const uint8_t KEY[] = { 0x20,0x9a,0x87,0xe3,0x78,0x87,0x7d,0x16,0xc7,0x20,0xfe,0xa1,0x4b,0xfa,0xd0,0x99 };
    const uint8_t IV[] = { 0x65,0x59,0xde,0x64,0xc4,0x17,0x74,0x6e,0x04,0xb0,0xba,0xfa,0x14,0xb4,0x5c,0x22 };
    const uint8_t PLAINTEXT[] = { 0x5f };
    const uint8_t CIPHERTEXT[] = { 0xf8 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CFB8MCT128-DECRYPT-99", "[CFB8][MCT][128][DECRYPT][n99]") {
    const uint8_t KEY[] = { 0xa1,0xad,0x67,0xc3,0x59,0x0d,0x1f,0x56,0xe3,0xf8,0x74,0xaa,0xba,0xd5,0x82,0xc6 };
    const uint8_t IV[] = { 0x81,0x37,0xe0,0x20,0x21,0x8a,0x62,0x40,0x24,0xd8,0x8a,0x0b,0xf1,0x2f,0x52,0x5f };
    const uint8_t PLAINTEXT[] = { 0xaf };
    const uint8_t CIPHERTEXT[] = { 0x54 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cfb8(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 9999; ++i) aes_decrypt_cfb8(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

