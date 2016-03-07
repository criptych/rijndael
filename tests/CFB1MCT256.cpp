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

TEST_CASE("CFB1MCT256-ENCRYPT-0", "[CFB1][MCT][256][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0x67,0xc3,0xe7,0xc5,0x80,0xbe,0x65,0x3a,0x92,0x76,0xb4,0x2e,0x51,0xa1,0x3d,0xb4,0x9b,0x71,0xfa,0x2f,0x51,0x19,0xe6,0xff,0x66,0x8e,0xb2,0x60,0x35,0x8a,0xba,0x8e };
    const uint8_t IV[] = { 0x88,0xbe,0x9b,0x76,0xc5,0xa8,0x3e,0xae,0xf4,0xd4,0xcd,0x04,0x25,0xe4,0xf5,0xc2 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-1", "[CFB1][MCT][256][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0x64,0x17,0xbd,0x48,0xa6,0x7a,0x36,0x79,0x0c,0xa3,0x7a,0xcf,0x08,0x7e,0x09,0xe1,0xa0,0xd5,0x53,0x88,0xbf,0xcd,0x36,0x50,0x6c,0x09,0x4e,0x1a,0xa3,0x82,0x2e,0x24 };
    const uint8_t IV[] = { 0x3b,0xa4,0xa9,0xa7,0xee,0xd4,0xd0,0xaf,0x0a,0x87,0xfc,0x7a,0x96,0x08,0x94,0xaa };
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

TEST_CASE("CFB1MCT256-ENCRYPT-2", "[CFB1][MCT][256][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0x7a,0xaa,0xc7,0xdd,0x0c,0x66,0x91,0x57,0xaa,0xcb,0xa2,0x88,0x62,0x58,0x0b,0x30,0x30,0x28,0x3e,0x7c,0x61,0x1b,0x3a,0x75,0x72,0x10,0x6a,0x33,0x99,0xfa,0x16,0x0e };
    const uint8_t IV[] = { 0x90,0xfd,0x6d,0xf4,0xde,0xd6,0x0c,0x25,0x1e,0x19,0x24,0x29,0x3a,0x78,0x38,0x2a };
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

TEST_CASE("CFB1MCT256-ENCRYPT-3", "[CFB1][MCT][256][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0x1e,0xea,0x15,0x5f,0x58,0xde,0x50,0xf9,0x1c,0x89,0x39,0x2a,0x0d,0xe5,0xe5,0x0b,0x29,0x23,0xc5,0xd3,0x31,0x46,0xb9,0xa7,0xfa,0x10,0x1e,0x25,0xc5,0x94,0x4d,0x6f };
    const uint8_t IV[] = { 0x19,0x0b,0xfb,0xaf,0x50,0x5d,0x83,0xd2,0x88,0x00,0x74,0x16,0x5c,0x6e,0x5b,0x61 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-4", "[CFB1][MCT][256][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0xf1,0x2f,0x46,0x42,0xee,0x54,0x01,0x7e,0xd9,0x34,0xf5,0xeb,0x56,0xcc,0xb4,0xf9,0xfd,0x10,0x38,0x7a,0x0c,0xea,0x53,0xb1,0xcf,0xa2,0x06,0x45,0xee,0x91,0xe7,0x5e };
    const uint8_t IV[] = { 0xd4,0x33,0xfd,0xa9,0x3d,0xac,0xea,0x16,0x35,0xb2,0x18,0x60,0x2b,0x05,0xaa,0x31 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-5", "[CFB1][MCT][256][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0x4f,0x45,0x7c,0x74,0x53,0x93,0x8a,0x46,0xf5,0xe9,0xb7,0x83,0x13,0x39,0x6e,0xe3,0xe5,0x66,0x4f,0x8e,0x3c,0x38,0xac,0xff,0x35,0x96,0xc8,0x4b,0x59,0xfa,0xb0,0x06 };
    const uint8_t IV[] = { 0x18,0x76,0x77,0xf4,0x30,0xd2,0xff,0x4e,0xfa,0x34,0xce,0x0e,0xb7,0x6b,0x57,0x58 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-6", "[CFB1][MCT][256][ENCRYPT][n6]") {
    const uint8_t KEY[] = { 0x66,0xfe,0x97,0x77,0x5d,0x6b,0xa8,0x34,0x05,0x97,0xa5,0x62,0x55,0x77,0x62,0x4c,0x7c,0x9f,0x36,0x94,0xe5,0x09,0x4e,0x43,0x0f,0xcd,0xed,0x71,0xa3,0x25,0x4f,0xb2 };
    const uint8_t IV[] = { 0x99,0xf9,0x79,0x1a,0xd9,0x31,0xe2,0xbc,0x3a,0x5b,0x25,0x3a,0xfa,0xdf,0xff,0xb4 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-7", "[CFB1][MCT][256][ENCRYPT][n7]") {
    const uint8_t KEY[] = { 0x19,0x11,0xa4,0x89,0xf6,0xbe,0x1b,0x16,0xf0,0xe1,0x90,0x20,0xec,0x24,0x50,0x30,0xc0,0x31,0xc2,0x11,0x2b,0xae,0xb6,0xd8,0xaf,0x57,0xbc,0x94,0xa2,0xb7,0x71,0xf6 };
    const uint8_t IV[] = { 0xbc,0xae,0xf4,0x85,0xce,0xa7,0xf8,0x9b,0xa0,0x9a,0x51,0xe5,0x01,0x92,0x3e,0x44 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-8", "[CFB1][MCT][256][ENCRYPT][n8]") {
    const uint8_t KEY[] = { 0x49,0xc1,0x9f,0x58,0x03,0x42,0xf9,0x60,0x64,0x42,0x14,0x21,0x35,0x07,0x67,0xe4,0xd4,0xc4,0xce,0x01,0x87,0x68,0x5c,0xb9,0x00,0x41,0x7d,0x74,0x7e,0x7c,0xc7,0x73 };
    const uint8_t IV[] = { 0x14,0xf5,0x0c,0x10,0xac,0xc6,0xea,0x61,0xaf,0x16,0xc1,0xe0,0xdc,0xcb,0xb6,0x85 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-9", "[CFB1][MCT][256][ENCRYPT][n9]") {
    const uint8_t KEY[] = { 0xff,0x57,0xc9,0x91,0x69,0x62,0xcd,0x3e,0xbc,0x33,0x35,0x47,0xe1,0x8b,0xc2,0x91,0xef,0x63,0x1c,0xd3,0x93,0x44,0xbe,0xbf,0x4c,0x66,0x59,0x56,0x5f,0x9b,0xb9,0x18 };
    const uint8_t IV[] = { 0x3b,0xa7,0xd2,0xd2,0x14,0x2c,0xe2,0x06,0x4c,0x27,0x24,0x22,0x21,0xe7,0x7e,0x6b };
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

TEST_CASE("CFB1MCT256-ENCRYPT-10", "[CFB1][MCT][256][ENCRYPT][n10]") {
    const uint8_t KEY[] = { 0x4f,0xe0,0xaf,0x91,0x1e,0x7b,0x2e,0xd7,0xa4,0xe2,0x43,0x12,0xa7,0x6e,0x18,0x03,0xb6,0x6f,0x1c,0xf8,0x11,0xf4,0x00,0xe8,0xa5,0xfc,0xff,0xce,0x40,0xf2,0x95,0x73 };
    const uint8_t IV[] = { 0x59,0x0c,0x00,0x2b,0x82,0xb0,0xbe,0x57,0xe9,0x9a,0xa6,0x98,0x1f,0x69,0x2c,0x6b };
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

TEST_CASE("CFB1MCT256-ENCRYPT-11", "[CFB1][MCT][256][ENCRYPT][n11]") {
    const uint8_t KEY[] = { 0x2a,0xfe,0xe1,0x7a,0x98,0x0d,0xac,0xa7,0x0f,0x8f,0xd3,0x44,0x96,0x7c,0xc6,0x35,0x99,0x6e,0x6d,0x97,0x9b,0x7e,0x63,0xa5,0x81,0x55,0x3c,0x54,0xb8,0xe8,0x01,0x90 };
    const uint8_t IV[] = { 0x2f,0x01,0x71,0x6f,0x8a,0x8a,0x63,0x4d,0x24,0xa9,0xc3,0x9a,0xf8,0x1a,0x94,0xe3 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-12", "[CFB1][MCT][256][ENCRYPT][n12]") {
    const uint8_t KEY[] = { 0x72,0x37,0xdc,0xd3,0x69,0xd3,0x3d,0xe5,0x20,0x29,0xac,0xb7,0xaa,0x16,0x9c,0xbe,0x62,0x16,0x0e,0x50,0xbc,0xc2,0xcb,0xca,0x51,0x04,0x4d,0xec,0xd6,0xa7,0xbd,0x8c };
    const uint8_t IV[] = { 0xfb,0x78,0x63,0xc7,0x27,0xbc,0xa8,0x6f,0xd0,0x51,0x71,0xb8,0x6e,0x4f,0xbc,0x1c };
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

TEST_CASE("CFB1MCT256-ENCRYPT-13", "[CFB1][MCT][256][ENCRYPT][n13]") {
    const uint8_t KEY[] = { 0xad,0x43,0xc2,0x2a,0x18,0x1d,0xcc,0x1b,0xbf,0x20,0x69,0xb6,0x4b,0x8e,0xee,0x7d,0xd0,0x5b,0xe6,0x88,0x44,0x07,0x6c,0xd8,0xb4,0x13,0x4b,0xfb,0x48,0xa6,0x70,0x7d };
    const uint8_t IV[] = { 0xb2,0x4d,0xe8,0xd8,0xf8,0xc5,0xa7,0x12,0xe5,0x17,0x06,0x17,0x9e,0x01,0xcd,0xf1 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-14", "[CFB1][MCT][256][ENCRYPT][n14]") {
    const uint8_t KEY[] = { 0x36,0xc5,0x86,0x61,0x53,0x68,0x38,0x8f,0xe6,0x51,0x2c,0x46,0x1b,0xb1,0xa1,0xce,0xb9,0x77,0xc2,0x58,0x1d,0x7a,0x14,0xc2,0x26,0xe1,0x0b,0x53,0xc9,0x27,0x39,0x51 };
    const uint8_t IV[] = { 0x69,0x2c,0x24,0xd0,0x59,0x7d,0x78,0x1a,0x92,0xf2,0x40,0xa8,0x81,0x81,0x49,0x2c };
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

TEST_CASE("CFB1MCT256-ENCRYPT-15", "[CFB1][MCT][256][ENCRYPT][n15]") {
    const uint8_t KEY[] = { 0x00,0x3a,0x99,0x0c,0x6a,0x11,0x43,0x70,0xad,0xe3,0x5c,0x3e,0xf9,0xe7,0x41,0x32,0x25,0x46,0x6b,0xf1,0x3f,0xdb,0x8e,0x02,0xd8,0x2d,0x26,0x19,0xb4,0xa5,0xa8,0x3e };
    const uint8_t IV[] = { 0x9c,0x31,0xa9,0xa9,0x22,0xa1,0x9a,0xc0,0xfe,0xcc,0x2d,0x4a,0x7d,0x82,0x91,0x6f };
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

TEST_CASE("CFB1MCT256-ENCRYPT-16", "[CFB1][MCT][256][ENCRYPT][n16]") {
    const uint8_t KEY[] = { 0x57,0x8a,0x73,0xf1,0x09,0xa7,0xce,0x1d,0x9b,0xd3,0xdc,0xdd,0x03,0x36,0x18,0xca,0x17,0x32,0x93,0x59,0xb9,0x8b,0xf7,0xe5,0x41,0x1c,0xf1,0x83,0xc4,0x68,0xf1,0x7f };
    const uint8_t IV[] = { 0x32,0x74,0xf8,0xa8,0x86,0x50,0x79,0xe7,0x99,0x31,0xd7,0x9a,0x70,0xcd,0x59,0x41 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-17", "[CFB1][MCT][256][ENCRYPT][n17]") {
    const uint8_t KEY[] = { 0x4f,0x77,0x9d,0x08,0xf6,0x9a,0x7c,0x6f,0x69,0x61,0x0a,0xb1,0xe5,0x24,0x6b,0xd4,0xa2,0x0c,0xdf,0x10,0x93,0x97,0xba,0xab,0x83,0x91,0xa1,0x8e,0x3b,0x4b,0x56,0xcb };
    const uint8_t IV[] = { 0xb5,0x3e,0x4c,0x49,0x2a,0x1c,0x4d,0x4e,0xc2,0x8d,0x50,0x0d,0xff,0x23,0xa7,0xb4 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-18", "[CFB1][MCT][256][ENCRYPT][n18]") {
    const uint8_t KEY[] = { 0x64,0x46,0xfd,0x37,0x59,0xd1,0x7d,0x68,0x57,0xb1,0xf5,0x2a,0x45,0x06,0x12,0x95,0x9b,0x10,0x26,0x17,0x9c,0xbd,0x39,0x81,0x82,0x9f,0x31,0x16,0x21,0xec,0xc3,0x31 };
    const uint8_t IV[] = { 0x39,0x1c,0xf9,0x07,0x0f,0x2a,0x83,0x2a,0x01,0x0e,0x90,0x98,0x1a,0xa7,0x95,0xfa };
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

TEST_CASE("CFB1MCT256-ENCRYPT-19", "[CFB1][MCT][256][ENCRYPT][n19]") {
    const uint8_t KEY[] = { 0x1d,0x1e,0x5f,0x42,0x7d,0x3a,0x35,0xe0,0xb5,0x24,0x74,0xb9,0x87,0x44,0x39,0xfd,0x06,0xda,0xb5,0x64,0x8b,0x02,0xa3,0xf2,0x9f,0xe9,0x65,0x0a,0xe6,0x74,0x8b,0x7a };
    const uint8_t IV[] = { 0x9d,0xca,0x93,0x73,0x17,0xbf,0x9a,0x73,0x1d,0x76,0x54,0x1c,0xc7,0x98,0x48,0x4b };
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

TEST_CASE("CFB1MCT256-ENCRYPT-20", "[CFB1][MCT][256][ENCRYPT][n20]") {
    const uint8_t KEY[] = { 0x7a,0xdb,0x70,0x9f,0xc4,0x4c,0xb5,0x64,0xce,0x0f,0xac,0xc1,0x13,0xcb,0xe0,0x7b,0x28,0x57,0xa1,0x44,0xb9,0xea,0x3a,0x3e,0xf7,0x03,0x12,0xb5,0xe1,0xef,0xc7,0xee };
    const uint8_t IV[] = { 0x2e,0x8d,0x14,0x20,0x32,0xe8,0x99,0xcc,0x68,0xea,0x77,0xbf,0x07,0x9b,0x4c,0x94 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-21", "[CFB1][MCT][256][ENCRYPT][n21]") {
    const uint8_t KEY[] = { 0x20,0x40,0x39,0xda,0xb8,0x88,0x6b,0xf6,0x6b,0x8c,0x27,0x13,0xcd,0xeb,0x57,0x1c,0x0a,0xa1,0xfa,0x6f,0x54,0x79,0x1b,0x17,0xee,0xf9,0xa8,0xc9,0x65,0xf0,0x4e,0x55 };
    const uint8_t IV[] = { 0x22,0xf6,0x5b,0x2b,0xed,0x93,0x21,0x29,0x19,0xfa,0xba,0x7c,0x84,0x1f,0x89,0xbb };
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

TEST_CASE("CFB1MCT256-ENCRYPT-22", "[CFB1][MCT][256][ENCRYPT][n22]") {
    const uint8_t KEY[] = { 0xda,0xd2,0x3f,0x2c,0x98,0x7a,0x4f,0x60,0x50,0x96,0xa2,0x27,0xf2,0x26,0x6b,0x03,0x9e,0xa8,0x1c,0x1a,0x4f,0xa9,0xfc,0xce,0x57,0xe9,0x5f,0xb5,0x10,0x93,0x8b,0x8d };
    const uint8_t IV[] = { 0x94,0x09,0xe6,0x75,0x1b,0xd0,0xe7,0xd9,0xb9,0x10,0xf7,0x7c,0x75,0x63,0xc5,0xd8 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-23", "[CFB1][MCT][256][ENCRYPT][n23]") {
    const uint8_t KEY[] = { 0x44,0x00,0xc9,0x89,0xe7,0xb1,0x48,0x4e,0xa3,0x7d,0xd5,0x00,0xcc,0xd8,0x72,0xf4,0xd1,0xfb,0x0c,0xa4,0x68,0x3b,0x94,0x9b,0x35,0x1e,0xef,0xef,0x4f,0x95,0xf3,0xe2 };
    const uint8_t IV[] = { 0x4f,0x53,0x10,0xbe,0x27,0x92,0x68,0x55,0x62,0xf7,0xb0,0x5a,0x5f,0x06,0x78,0x6f };
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

TEST_CASE("CFB1MCT256-ENCRYPT-24", "[CFB1][MCT][256][ENCRYPT][n24]") {
    const uint8_t KEY[] = { 0x21,0x47,0x29,0x01,0xd1,0x1d,0xc4,0x8e,0x0a,0x38,0x13,0x7b,0xab,0xc9,0x5f,0x69,0xc3,0xb6,0x14,0x60,0x72,0xee,0x7f,0x78,0x23,0x5a,0x54,0xc1,0xfb,0x32,0x0e,0x74 };
    const uint8_t IV[] = { 0x12,0x4d,0x18,0xc4,0x1a,0xd5,0xeb,0xe3,0x16,0x44,0xbb,0x2e,0xb4,0xa7,0xfd,0x96 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-25", "[CFB1][MCT][256][ENCRYPT][n25]") {
    const uint8_t KEY[] = { 0x21,0x3e,0x21,0x61,0x1e,0x36,0x8d,0x4d,0x63,0xa0,0x4b,0xb0,0x10,0x1d,0xdf,0x1c,0x17,0xfa,0x32,0xd0,0x8e,0x3d,0xad,0xa7,0x3d,0xa6,0x55,0xab,0x65,0x8f,0x55,0x1e };
    const uint8_t IV[] = { 0xd4,0x4c,0x26,0xb0,0xfc,0xd3,0xd2,0xdf,0x1e,0xfc,0x01,0x6a,0x9e,0xbd,0x5b,0x6a };
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

TEST_CASE("CFB1MCT256-ENCRYPT-26", "[CFB1][MCT][256][ENCRYPT][n26]") {
    const uint8_t KEY[] = { 0xb8,0xfb,0x3c,0x26,0xe9,0x72,0x97,0x6b,0xf3,0x8d,0x5c,0x60,0x45,0x77,0xe9,0xa2,0xec,0x8c,0x99,0x92,0x0c,0x8a,0x0e,0x89,0xc5,0xef,0x06,0x22,0x65,0xf5,0x1d,0xdd };
    const uint8_t IV[] = { 0xfb,0x76,0xab,0x42,0x82,0xb7,0xa3,0x2e,0xf8,0x49,0x53,0x89,0x00,0x7a,0x48,0xc3 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-27", "[CFB1][MCT][256][ENCRYPT][n27]") {
    const uint8_t KEY[] = { 0xc7,0xe7,0x44,0xb1,0xff,0x1c,0x77,0xbd,0xc4,0x2c,0x42,0xf0,0x80,0xc4,0x17,0x38,0xe3,0x79,0xb2,0xe2,0x08,0x6c,0x5a,0xf1,0x6d,0x0f,0x34,0x9f,0xd3,0xc3,0xa5,0x6b };
    const uint8_t IV[] = { 0x0f,0xf5,0x2b,0x70,0x04,0xe6,0x54,0x78,0xa8,0xe0,0x32,0xbd,0xb6,0x36,0xb8,0xb6 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-28", "[CFB1][MCT][256][ENCRYPT][n28]") {
    const uint8_t KEY[] = { 0xb1,0x81,0x86,0x06,0x43,0x10,0x13,0x43,0x9c,0x52,0x5d,0x19,0x06,0xbb,0x91,0x2d,0x22,0x05,0x2b,0x4c,0x51,0x69,0x17,0xc1,0x68,0xa2,0x80,0x82,0xba,0x34,0x0a,0x08 };
    const uint8_t IV[] = { 0xc1,0x7c,0x99,0xae,0x59,0x05,0x4d,0x30,0x05,0xad,0xb4,0x1d,0x69,0xf7,0xaf,0x63 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-29", "[CFB1][MCT][256][ENCRYPT][n29]") {
    const uint8_t KEY[] = { 0x5a,0x89,0x93,0x39,0x0c,0xea,0xa4,0xfc,0xd0,0xd6,0xb0,0x48,0xe5,0x03,0x4c,0x68,0x5b,0xc9,0xe9,0xad,0x85,0xe0,0x8d,0x2d,0xa4,0x5f,0x2b,0x58,0x7f,0x8f,0xe4,0x57 };
    const uint8_t IV[] = { 0x79,0xcc,0xc2,0xe1,0xd4,0x89,0x9a,0xec,0xcc,0xfd,0xab,0xda,0xc5,0xbb,0xee,0x5f };
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

TEST_CASE("CFB1MCT256-ENCRYPT-30", "[CFB1][MCT][256][ENCRYPT][n30]") {
    const uint8_t KEY[] = { 0x59,0x1c,0xfd,0xd8,0xf8,0x5c,0x4c,0xae,0x28,0x18,0x9a,0x35,0x0c,0x77,0x43,0x5d,0x60,0xda,0x33,0x55,0xa2,0xc7,0x03,0x65,0x2e,0x3c,0x0a,0x9d,0xa8,0x23,0x4d,0xf1 };
    const uint8_t IV[] = { 0x3b,0x13,0xda,0xf8,0x27,0x27,0x8e,0x48,0x8a,0x63,0x21,0xc5,0xd7,0xac,0xa9,0xa6 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-31", "[CFB1][MCT][256][ENCRYPT][n31]") {
    const uint8_t KEY[] = { 0x3c,0x42,0x6a,0x6f,0xf3,0xec,0x30,0x1b,0x87,0x2f,0x61,0x29,0x21,0x2a,0x83,0x10,0x82,0xf6,0xb8,0x98,0xbb,0x3c,0xbf,0x39,0x50,0x1a,0x39,0x15,0x9e,0x86,0x73,0xdf };
    const uint8_t IV[] = { 0xe2,0x2c,0x8b,0xcd,0x19,0xfb,0xbc,0x5c,0x7e,0x26,0x33,0x88,0x36,0xa5,0x3e,0x2e };
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

TEST_CASE("CFB1MCT256-ENCRYPT-32", "[CFB1][MCT][256][ENCRYPT][n32]") {
    const uint8_t KEY[] = { 0x05,0xd0,0xf5,0xde,0x2f,0x91,0x86,0x76,0xdc,0x6f,0xde,0x2f,0x25,0xbe,0x3f,0xbc,0xb2,0xe0,0x10,0x94,0x5d,0x0e,0x21,0xb9,0x54,0x09,0xe1,0x0a,0x5f,0x07,0x67,0x23 };
    const uint8_t IV[] = { 0x30,0x16,0xa8,0x0c,0xe6,0x32,0x9e,0x80,0x04,0x13,0xd8,0x1f,0xc1,0x81,0x14,0xfc };
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

TEST_CASE("CFB1MCT256-ENCRYPT-33", "[CFB1][MCT][256][ENCRYPT][n33]") {
    const uint8_t KEY[] = { 0x07,0xb5,0x81,0x41,0x83,0x32,0x59,0xf5,0x25,0x7c,0xb0,0x61,0x80,0x75,0xbe,0xbd,0xe8,0xcc,0x76,0x37,0x69,0x73,0xd9,0x89,0x77,0x82,0x11,0xb4,0xb8,0xda,0xfa,0x66 };
    const uint8_t IV[] = { 0x5a,0x2c,0x66,0xa3,0x34,0x7d,0xf8,0x30,0x23,0x8b,0xf0,0xbe,0xe7,0xdd,0x9d,0x45 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-34", "[CFB1][MCT][256][ENCRYPT][n34]") {
    const uint8_t KEY[] = { 0x1b,0xe4,0xa3,0x53,0xb2,0x57,0xa4,0xd6,0x8d,0x76,0xe2,0xd4,0x7c,0x58,0x80,0xd6,0x15,0x40,0x5c,0xfa,0xed,0x54,0x0d,0x07,0x85,0xf4,0x5e,0x18,0x4b,0x76,0xb7,0xda };
    const uint8_t IV[] = { 0xfd,0x8c,0x2a,0xcd,0x84,0x27,0xd4,0x8e,0xf2,0x76,0x4f,0xac,0xf3,0xac,0x4d,0xbc };
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

TEST_CASE("CFB1MCT256-ENCRYPT-35", "[CFB1][MCT][256][ENCRYPT][n35]") {
    const uint8_t KEY[] = { 0x2b,0xa1,0xf0,0x1c,0xc1,0x19,0x4d,0x04,0xb9,0x86,0x93,0x9f,0xbc,0xf3,0x08,0xc6,0x90,0x53,0x64,0x1c,0xc1,0xa7,0x6b,0xb0,0xbd,0xde,0x37,0xe2,0x44,0xe7,0x7b,0x72 };
    const uint8_t IV[] = { 0x85,0x13,0x38,0xe6,0x2c,0xf3,0x66,0xb7,0x38,0x2a,0x69,0xfa,0x0f,0x91,0xcc,0xa8 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-36", "[CFB1][MCT][256][ENCRYPT][n36]") {
    const uint8_t KEY[] = { 0x47,0xfe,0x37,0xad,0xb0,0xc0,0xbb,0xa0,0x7d,0xca,0x8f,0x7e,0x90,0x58,0x40,0x05,0x77,0xbe,0x69,0xc2,0x77,0xe1,0x58,0x4a,0xe8,0x64,0x0e,0xe0,0x9f,0x6c,0x2d,0x39 };
    const uint8_t IV[] = { 0xe7,0xed,0x0d,0xde,0xb6,0x46,0x33,0xfa,0x55,0xba,0x39,0x02,0xdb,0x8b,0x56,0x4b };
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

TEST_CASE("CFB1MCT256-ENCRYPT-37", "[CFB1][MCT][256][ENCRYPT][n37]") {
    const uint8_t KEY[] = { 0xd9,0x03,0x14,0x3f,0xfd,0x14,0x72,0xc1,0x60,0x9d,0x25,0xfb,0x58,0xbe,0x77,0xac,0x92,0xd2,0xae,0x9c,0xfd,0x4c,0xd8,0x6b,0x8a,0x51,0x0a,0xda,0x61,0x8d,0x94,0xe3 };
    const uint8_t IV[] = { 0xe5,0x6c,0xc7,0x5e,0x8a,0xad,0x80,0x21,0x62,0x35,0x04,0x3a,0xfe,0xe1,0xb9,0xda };
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

TEST_CASE("CFB1MCT256-ENCRYPT-38", "[CFB1][MCT][256][ENCRYPT][n38]") {
    const uint8_t KEY[] = { 0x95,0x07,0x44,0xe7,0xdb,0xc1,0x43,0x5c,0xf5,0xdf,0x0c,0xb3,0x0b,0xf8,0x8b,0x31,0x5a,0x84,0xb7,0xfb,0x47,0x19,0xb5,0xc0,0xe9,0x42,0xdb,0xbb,0x40,0xe7,0xf9,0x94 };
    const uint8_t IV[] = { 0xc8,0x56,0x19,0x67,0xba,0x55,0x6d,0xab,0x63,0x13,0xd1,0x61,0x21,0x6a,0x6d,0x77 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-39", "[CFB1][MCT][256][ENCRYPT][n39]") {
    const uint8_t KEY[] = { 0xbe,0x52,0xc5,0x2f,0x90,0xa4,0x78,0xab,0x86,0x36,0xcd,0x9c,0x54,0x82,0x10,0x08,0xe5,0xc8,0x44,0x1b,0xa4,0xcc,0x2f,0xc1,0x55,0x60,0x87,0x29,0xf5,0x11,0xef,0xb2 };
    const uint8_t IV[] = { 0xbf,0x4c,0xf3,0xe0,0xe3,0xd5,0x9a,0x01,0xbc,0x22,0x5c,0x92,0xb5,0xf6,0x16,0x26 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-40", "[CFB1][MCT][256][ENCRYPT][n40]") {
    const uint8_t KEY[] = { 0x44,0x16,0x42,0x6c,0x63,0xb2,0x50,0x6b,0x69,0xfe,0xdb,0x7b,0xc6,0xfd,0x3e,0xd0,0x4b,0xd1,0xba,0xcb,0x2b,0x14,0x74,0xe2,0xb9,0xa2,0x5e,0xbd,0xb8,0xde,0x36,0xe7 };
    const uint8_t IV[] = { 0xae,0x19,0xfe,0xd0,0x8f,0xd8,0x5b,0x23,0xec,0xc2,0xd9,0x94,0x4d,0xcf,0xd9,0x55 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-41", "[CFB1][MCT][256][ENCRYPT][n41]") {
    const uint8_t KEY[] = { 0xa7,0xab,0x5f,0xd4,0x0c,0x71,0x50,0x45,0x3e,0x5f,0x25,0x03,0x67,0x30,0xd0,0x40,0x2d,0x72,0x0f,0x32,0xe7,0x1e,0x91,0xfa,0x32,0x25,0xd5,0xb0,0xf5,0x9e,0x52,0xc2 };
    const uint8_t IV[] = { 0x66,0xa3,0xb5,0xf9,0xcc,0x0a,0xe5,0x18,0x8b,0x87,0x8b,0x0d,0x4d,0x40,0x64,0x25 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-42", "[CFB1][MCT][256][ENCRYPT][n42]") {
    const uint8_t KEY[] = { 0xcc,0xe9,0x57,0x8d,0x07,0xd9,0xd0,0x36,0x31,0xc3,0x2a,0x95,0xb5,0xeb,0x9e,0x67,0x27,0x91,0x6a,0x28,0x04,0xac,0xe1,0x28,0xed,0xde,0x62,0xe6,0x7d,0x9c,0xf1,0xf5 };
    const uint8_t IV[] = { 0x0a,0xe3,0x65,0x1a,0xe3,0xb2,0x70,0xd2,0xdf,0xfb,0xb7,0x56,0x88,0x02,0xa3,0x37 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-43", "[CFB1][MCT][256][ENCRYPT][n43]") {
    const uint8_t KEY[] = { 0x34,0x45,0x26,0x26,0x9b,0x54,0x21,0x78,0xd6,0x05,0xb4,0xc9,0xea,0x1f,0xc5,0x39,0x04,0xd7,0xe0,0x70,0x5e,0x07,0xeb,0x9f,0x7a,0xb5,0xb2,0xfd,0x2a,0x0f,0xa2,0xb3 };
    const uint8_t IV[] = { 0x23,0x46,0x8a,0x58,0x5a,0xab,0x0a,0xb7,0x97,0x6b,0xd0,0x1b,0x57,0x93,0x53,0x46 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-44", "[CFB1][MCT][256][ENCRYPT][n44]") {
    const uint8_t KEY[] = { 0xa3,0x1c,0x18,0x84,0xf3,0x6c,0x99,0xcb,0xaa,0xd7,0x81,0x2f,0x72,0x6e,0x09,0x4d,0x46,0xda,0xad,0x6d,0xb7,0xb2,0xf4,0xfd,0x15,0x78,0xac,0xaf,0x89,0x31,0xfd,0x30 };
    const uint8_t IV[] = { 0x42,0x0d,0x4d,0x1d,0xe9,0xb5,0x1f,0x62,0x6f,0xcd,0x1e,0x52,0xa3,0x3e,0x5f,0x83 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-45", "[CFB1][MCT][256][ENCRYPT][n45]") {
    const uint8_t KEY[] = { 0x45,0x2f,0xcd,0x71,0x9c,0x9d,0xdc,0xd5,0x39,0xa9,0xc6,0x83,0x18,0x52,0x46,0x6e,0x47,0xa2,0xf1,0xac,0x53,0x84,0x99,0x35,0xfa,0x1b,0x42,0x98,0xe6,0x3a,0xce,0x4b };
    const uint8_t IV[] = { 0x01,0x78,0x5c,0xc1,0xe4,0x36,0x6d,0xc8,0xef,0x63,0xee,0x37,0x6f,0x0b,0x33,0x7b };
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

TEST_CASE("CFB1MCT256-ENCRYPT-46", "[CFB1][MCT][256][ENCRYPT][n46]") {
    const uint8_t KEY[] = { 0xbc,0x9c,0xca,0x93,0xa9,0x5b,0x2f,0x1c,0x69,0xc1,0x25,0x70,0x77,0x95,0xe0,0xf9,0x33,0x3a,0x33,0x9f,0x12,0xe0,0x8a,0xb3,0x8b,0x86,0xfa,0x80,0x87,0x56,0x42,0x63 };
    const uint8_t IV[] = { 0x74,0x98,0xc2,0x33,0x41,0x64,0x13,0x86,0x71,0x9d,0xb8,0x18,0x61,0x6c,0x8c,0x28 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-47", "[CFB1][MCT][256][ENCRYPT][n47]") {
    const uint8_t KEY[] = { 0xa5,0x2c,0x7e,0xa1,0x92,0x10,0x85,0x39,0x40,0x8f,0x17,0x88,0xbe,0x58,0x57,0xa5,0x50,0xae,0x3a,0x4b,0xdc,0x8d,0x5b,0xfb,0xfa,0x9b,0xa4,0x54,0xb4,0xd0,0x1e,0x8f };
    const uint8_t IV[] = { 0x63,0x94,0x09,0xd4,0xce,0x6d,0xd1,0x48,0x71,0x1d,0x5e,0xd4,0x33,0x86,0x5c,0xec };
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

TEST_CASE("CFB1MCT256-ENCRYPT-48", "[CFB1][MCT][256][ENCRYPT][n48]") {
    const uint8_t KEY[] = { 0x92,0x29,0x98,0x7d,0xa2,0xd8,0x2e,0x50,0xbd,0xd5,0xd1,0x61,0xdc,0x39,0xee,0xfb,0x57,0x0c,0xb3,0xd7,0x07,0xaa,0xd0,0xbf,0x5e,0x10,0x17,0x14,0x61,0x4d,0x98,0xb0 };
    const uint8_t IV[] = { 0x07,0xa2,0x89,0x9c,0xdb,0x27,0x8b,0x44,0xa4,0x8b,0xb3,0x40,0xd5,0x9d,0x86,0x3f };
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

TEST_CASE("CFB1MCT256-ENCRYPT-49", "[CFB1][MCT][256][ENCRYPT][n49]") {
    const uint8_t KEY[] = { 0x6b,0x7f,0xb0,0xe8,0xcb,0xd7,0x5f,0x20,0xe4,0xd6,0x88,0xfa,0x4b,0x7c,0x68,0x9e,0x37,0x4b,0x7e,0xe0,0xdb,0x5f,0x6d,0x2b,0x4d,0xf1,0x0a,0x53,0x8f,0x28,0x0e,0x2b };
    const uint8_t IV[] = { 0x60,0x47,0xcd,0x37,0xdc,0xf5,0xbd,0x94,0x13,0xe1,0x1d,0x47,0xee,0x65,0x96,0x9b };
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

TEST_CASE("CFB1MCT256-ENCRYPT-50", "[CFB1][MCT][256][ENCRYPT][n50]") {
    const uint8_t KEY[] = { 0x81,0x49,0xa7,0x82,0x12,0x58,0x07,0x3b,0x4e,0x94,0x37,0x6d,0x78,0x8f,0xae,0x93,0x6c,0x23,0x06,0x8e,0xf2,0x10,0xf3,0x91,0x11,0x33,0x9e,0x1d,0x49,0xfd,0x73,0x32 };
    const uint8_t IV[] = { 0x5b,0x68,0x78,0x6e,0x29,0x4f,0x9e,0xba,0x5c,0xc2,0x94,0x4e,0xc6,0xd5,0x7d,0x19 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-51", "[CFB1][MCT][256][ENCRYPT][n51]") {
    const uint8_t KEY[] = { 0xda,0xa2,0x75,0xbc,0x1d,0x93,0xb1,0xc5,0xe3,0x22,0xaa,0x31,0x74,0x8f,0xff,0x31,0xe9,0xab,0x9a,0x5a,0xaf,0x39,0x5d,0x69,0x54,0xbc,0x6e,0x92,0xec,0xd5,0xbd,0x73 };
    const uint8_t IV[] = { 0x85,0x88,0x9c,0xd4,0x5d,0x29,0xae,0xf8,0x45,0x8f,0xf0,0x8f,0xa5,0x28,0xce,0x41 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-52", "[CFB1][MCT][256][ENCRYPT][n52]") {
    const uint8_t KEY[] = { 0x33,0xa2,0x4b,0x78,0xa7,0xd5,0x70,0x32,0x27,0xda,0x4d,0x4e,0x37,0x8a,0xf5,0xba,0x3a,0xde,0xd9,0x9c,0x6c,0xcb,0x31,0x2a,0xf6,0x1d,0x2f,0xa2,0x17,0x32,0xac,0xff };
    const uint8_t IV[] = { 0xd3,0x75,0x43,0xc6,0xc3,0xf2,0x6c,0x43,0xa2,0xa1,0x41,0x30,0xfb,0xe7,0x11,0x8c };
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

TEST_CASE("CFB1MCT256-ENCRYPT-53", "[CFB1][MCT][256][ENCRYPT][n53]") {
    const uint8_t KEY[] = { 0xa1,0xa6,0xc9,0xfc,0x3f,0x40,0x85,0xf3,0x27,0xeb,0xa8,0xad,0x65,0xaa,0xa1,0x07,0x05,0x4b,0xa1,0xac,0x2e,0xc7,0xff,0x36,0x9d,0x01,0x4c,0x0d,0x59,0x9f,0x69,0x7f };
    const uint8_t IV[] = { 0x3f,0x95,0x78,0x30,0x42,0x0c,0xce,0x1c,0x6b,0x1c,0x63,0xaf,0x4e,0xad,0xc5,0x80 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-54", "[CFB1][MCT][256][ENCRYPT][n54]") {
    const uint8_t KEY[] = { 0xc5,0x8a,0x7e,0xc4,0xe3,0x49,0x78,0x9b,0x20,0xc3,0x06,0x55,0xf5,0xfd,0xdc,0x7a,0xf8,0x3a,0x9a,0x9f,0x7d,0x57,0x76,0x18,0x81,0x8e,0x79,0x7a,0xa4,0xcc,0x58,0x34 };
    const uint8_t IV[] = { 0xfd,0x71,0x3b,0x33,0x53,0x90,0x89,0x2e,0x1c,0x8f,0x35,0x77,0xfd,0x53,0x31,0x4b };
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

TEST_CASE("CFB1MCT256-ENCRYPT-55", "[CFB1][MCT][256][ENCRYPT][n55]") {
    const uint8_t KEY[] = { 0xdc,0x9e,0x19,0x2f,0x23,0x21,0xd6,0xb3,0x76,0x5d,0x58,0x25,0xee,0x6c,0x79,0x29,0xd4,0xf4,0x0f,0xc7,0xde,0x20,0x46,0x0d,0xc3,0x66,0xb1,0xf5,0xaa,0x3e,0xaf,0x8e };
    const uint8_t IV[] = { 0x2c,0xce,0x95,0x58,0xa3,0x77,0x30,0x15,0x42,0xe8,0xc8,0x8f,0x0e,0xf2,0xf7,0xba };
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

TEST_CASE("CFB1MCT256-ENCRYPT-56", "[CFB1][MCT][256][ENCRYPT][n56]") {
    const uint8_t KEY[] = { 0x5f,0x3c,0x4a,0xb0,0xea,0x5c,0x40,0x68,0x4a,0xba,0x76,0x66,0x10,0xfd,0xc1,0x9f,0x2d,0x78,0x98,0xcd,0x26,0x97,0x9d,0x45,0x62,0xc8,0x4c,0x39,0x5d,0x65,0xe7,0x68 };
    const uint8_t IV[] = { 0xf9,0x8c,0x97,0x0a,0xf8,0xb7,0xdb,0x48,0xa1,0xae,0xfd,0xcc,0xf7,0x5b,0x48,0xe6 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-57", "[CFB1][MCT][256][ENCRYPT][n57]") {
    const uint8_t KEY[] = { 0x95,0xb4,0x0f,0x3c,0x4c,0x8f,0x4e,0x12,0x96,0xcc,0xea,0x68,0x6b,0xa9,0x84,0x4b,0xff,0xb2,0x1c,0x75,0x9c,0x7d,0x02,0xd4,0x99,0x15,0x63,0x52,0x06,0xc0,0xb1,0x8a };
    const uint8_t IV[] = { 0xd2,0xca,0x84,0xb8,0xba,0xea,0x9f,0x91,0xfb,0xdd,0x2f,0x6b,0x5b,0xa5,0x56,0xe2 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-58", "[CFB1][MCT][256][ENCRYPT][n58]") {
    const uint8_t KEY[] = { 0x4b,0xa4,0x11,0x5b,0xba,0x38,0x25,0x2e,0x98,0x1f,0xa9,0x9f,0x1e,0xa5,0x00,0x70,0x0d,0xa1,0xf5,0xc2,0x35,0xa5,0xc2,0x60,0x89,0xaf,0x55,0x78,0x1c,0x9f,0x36,0x74 };
    const uint8_t IV[] = { 0xf2,0x13,0xe9,0xb7,0xa9,0xd8,0xc0,0xb4,0x10,0xba,0x36,0x2a,0x1a,0x5f,0x87,0xfe };
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

TEST_CASE("CFB1MCT256-ENCRYPT-59", "[CFB1][MCT][256][ENCRYPT][n59]") {
    const uint8_t KEY[] = { 0x74,0xf0,0xcd,0xaa,0x41,0xd9,0x0a,0x92,0x58,0x3b,0x6a,0xe4,0x74,0xc8,0xe2,0x87,0xfd,0x7e,0x36,0x89,0xb4,0x68,0x23,0x31,0x43,0x82,0xd2,0xf7,0xbf,0x2c,0x78,0x54 };
    const uint8_t IV[] = { 0xf0,0xdf,0xc3,0x4b,0x81,0xcd,0xe1,0x51,0xca,0x2d,0x87,0x8f,0xa3,0xb3,0x4e,0x20 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-60", "[CFB1][MCT][256][ENCRYPT][n60]") {
    const uint8_t KEY[] = { 0x72,0x35,0x59,0xf3,0x66,0xd6,0x6b,0x88,0x48,0xd9,0x1f,0xf0,0x61,0x7b,0xdd,0xb8,0x36,0xd3,0x17,0x79,0x8e,0x26,0x27,0x26,0x74,0x93,0x24,0xa4,0xf5,0x2a,0x2b,0x5d };
    const uint8_t IV[] = { 0xcb,0xad,0x21,0xf0,0x3a,0x4e,0x04,0x17,0x37,0x11,0xf6,0x53,0x4a,0x06,0x53,0x09 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-61", "[CFB1][MCT][256][ENCRYPT][n61]") {
    const uint8_t KEY[] = { 0xcd,0x77,0xc6,0xa4,0x04,0x13,0x35,0x75,0xc2,0x9a,0x40,0x8c,0xac,0xb0,0x6f,0xa6,0x40,0x40,0x0c,0x9d,0xa1,0xb9,0x34,0x93,0x36,0x77,0x06,0x24,0x71,0xb0,0xcc,0x12 };
    const uint8_t IV[] = { 0x76,0x93,0x1b,0xe4,0x2f,0x9f,0x13,0xb5,0x42,0xe4,0x22,0x80,0x84,0x9a,0xe7,0x4f };
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

TEST_CASE("CFB1MCT256-ENCRYPT-62", "[CFB1][MCT][256][ENCRYPT][n62]") {
    const uint8_t KEY[] = { 0xb2,0x6f,0x34,0x87,0xa9,0x25,0x42,0x48,0xf8,0x4f,0x8c,0x28,0xfe,0x57,0x2b,0x0d,0x83,0xbe,0x16,0x36,0x4b,0xa4,0x89,0x1f,0x49,0x89,0x9e,0x38,0x8d,0x56,0x0e,0xee };
    const uint8_t IV[] = { 0xc3,0xfe,0x1a,0xab,0xea,0x1d,0xbd,0x8c,0x7f,0xfe,0x98,0x1c,0xfc,0xe6,0xc2,0xfc };
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

TEST_CASE("CFB1MCT256-ENCRYPT-63", "[CFB1][MCT][256][ENCRYPT][n63]") {
    const uint8_t KEY[] = { 0xcb,0xe4,0x0c,0xe3,0xd4,0xfe,0xe9,0x38,0x23,0x4e,0xfa,0x5f,0x29,0x42,0x68,0x4b,0x43,0xc9,0xdf,0x7b,0xc8,0x07,0x2b,0x3e,0xc2,0x3a,0xf4,0xbc,0x7e,0xe8,0xcf,0xd6 };
    const uint8_t IV[] = { 0xc0,0x77,0xc9,0x4d,0x83,0xa3,0xa2,0x21,0x8b,0xb3,0x6a,0x84,0xf3,0xbe,0xc1,0x38 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-64", "[CFB1][MCT][256][ENCRYPT][n64]") {
    const uint8_t KEY[] = { 0x89,0xdb,0xc3,0xd9,0x5f,0x54,0xe5,0xfd,0xc6,0x1e,0x8f,0x83,0x5e,0xbd,0x94,0xa2,0x47,0xbf,0x40,0x72,0xe3,0xcd,0xb5,0x12,0xba,0x67,0x04,0x32,0xbb,0xca,0x8e,0x4d };
    const uint8_t IV[] = { 0x04,0x76,0x9f,0x09,0x2b,0xca,0x9e,0x2c,0x78,0x5d,0xf0,0x8e,0xc5,0x22,0x41,0x9b };
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

TEST_CASE("CFB1MCT256-ENCRYPT-65", "[CFB1][MCT][256][ENCRYPT][n65]") {
    const uint8_t KEY[] = { 0xaa,0x42,0xee,0x95,0x6f,0x14,0xb3,0x63,0xd0,0x35,0x26,0xaf,0x7c,0x35,0x0a,0xc8,0xec,0xce,0x5c,0xef,0x74,0x14,0xe2,0xb7,0xf4,0x1a,0xac,0xb3,0x64,0x07,0x7a,0x57 };
    const uint8_t IV[] = { 0xab,0x71,0x1c,0x9d,0x97,0xd9,0x57,0xa5,0x4e,0x7d,0xa8,0x81,0xdf,0xcd,0xf4,0x1a };
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

TEST_CASE("CFB1MCT256-ENCRYPT-66", "[CFB1][MCT][256][ENCRYPT][n66]") {
    const uint8_t KEY[] = { 0x14,0x63,0x23,0x59,0xf1,0x68,0xac,0x06,0x6b,0xdd,0x28,0x59,0x2f,0xf5,0x4e,0x34,0x87,0x69,0xe0,0x84,0x0e,0xcf,0x86,0x79,0x93,0x48,0x3f,0x5b,0xec,0x45,0xc2,0xa5 };
    const uint8_t IV[] = { 0x6b,0xa7,0xbc,0x6b,0x7a,0xdb,0x64,0xce,0x67,0x52,0x93,0xe8,0x88,0x42,0xb8,0xf2 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-67", "[CFB1][MCT][256][ENCRYPT][n67]") {
    const uint8_t KEY[] = { 0x59,0xd7,0xe2,0xd3,0x1e,0xe5,0x58,0xc8,0x5e,0x4a,0xeb,0x16,0x42,0xbd,0xd9,0xe2,0x45,0x24,0x35,0x6b,0xd9,0xf4,0xe2,0x07,0x0f,0x01,0x00,0xeb,0xed,0x2c,0x3d,0x54 };
    const uint8_t IV[] = { 0xc2,0x4d,0xd5,0xef,0xd7,0x3b,0x64,0x7e,0x9c,0x49,0x3f,0xb0,0x01,0x69,0xff,0xf1 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-68", "[CFB1][MCT][256][ENCRYPT][n68]") {
    const uint8_t KEY[] = { 0x43,0x90,0xc4,0x98,0xe7,0xd3,0xe1,0x45,0x90,0xca,0x51,0xf9,0xbb,0xe0,0xdc,0x5c,0xc1,0x47,0x22,0x99,0x7f,0xb1,0xe4,0x4d,0x41,0xe7,0xb7,0x65,0xc1,0x39,0x10,0xed };
    const uint8_t IV[] = { 0x84,0x63,0x17,0xf2,0xa6,0x45,0x06,0x4a,0x4e,0xe6,0xb7,0x8e,0x2c,0x15,0x2d,0xb9 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-69", "[CFB1][MCT][256][ENCRYPT][n69]") {
    const uint8_t KEY[] = { 0xc8,0xe5,0x70,0x45,0x57,0x97,0x3f,0x33,0x46,0x51,0xcd,0x8f,0xf4,0xcb,0xe0,0x00,0xc9,0x8f,0x2b,0x25,0x29,0x07,0xcb,0x17,0xf1,0x7c,0x27,0x24,0x4d,0x37,0xc6,0x43 };
    const uint8_t IV[] = { 0x08,0xc8,0x09,0xbc,0x56,0xb6,0x2f,0x5a,0xb0,0x9b,0x90,0x41,0x8c,0x0e,0xd6,0xae };
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

TEST_CASE("CFB1MCT256-ENCRYPT-70", "[CFB1][MCT][256][ENCRYPT][n70]") {
    const uint8_t KEY[] = { 0x29,0xc9,0x2f,0xdc,0x1f,0xf8,0x71,0xb1,0x77,0x26,0x70,0x0d,0x26,0x0b,0x82,0xe7,0x9a,0x9f,0xa9,0xd4,0x4e,0xc1,0x7a,0x7a,0xc5,0x43,0x06,0x9e,0xec,0x1a,0x7b,0x80 };
    const uint8_t IV[] = { 0x53,0x10,0x82,0xf1,0x67,0xc6,0xb1,0x6d,0x34,0x3f,0x21,0xba,0xa1,0x2d,0xbd,0xc3 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-71", "[CFB1][MCT][256][ENCRYPT][n71]") {
    const uint8_t KEY[] = { 0xf0,0xd5,0xfc,0xa8,0xec,0xe7,0xfe,0x18,0x47,0x65,0x7d,0xe4,0x50,0xd8,0xbb,0xbb,0x5d,0x55,0xd7,0xcb,0x05,0x1a,0xec,0xf2,0x2a,0xc5,0x6f,0x01,0x18,0xe0,0x53,0x1e };
    const uint8_t IV[] = { 0xc7,0xca,0x7e,0x1f,0x4b,0xdb,0x96,0x88,0xef,0x86,0x69,0x9f,0xf4,0xfa,0x28,0x9e };
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

TEST_CASE("CFB1MCT256-ENCRYPT-72", "[CFB1][MCT][256][ENCRYPT][n72]") {
    const uint8_t KEY[] = { 0x83,0xd2,0x69,0x0a,0xa9,0x35,0x46,0xba,0xbf,0x1b,0x49,0xfe,0x45,0x70,0x43,0x32,0xa1,0x47,0xf2,0xbb,0x03,0xd5,0x52,0x84,0xc6,0x3a,0x15,0x7a,0xcb,0xcc,0x65,0xca };
    const uint8_t IV[] = { 0xfc,0x12,0x25,0x70,0x06,0xcf,0xbe,0x76,0xec,0xff,0x7a,0x7b,0xd3,0x2c,0x36,0xd4 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-73", "[CFB1][MCT][256][ENCRYPT][n73]") {
    const uint8_t KEY[] = { 0x13,0x1d,0xe3,0x09,0x91,0x2c,0xce,0x3d,0x95,0x26,0x81,0xc3,0x9c,0x34,0xfa,0x72,0x03,0xa2,0x0b,0xc6,0xee,0x7b,0xbc,0x6a,0x0a,0x74,0x91,0xbc,0x43,0x24,0xe2,0xe4 };
    const uint8_t IV[] = { 0xa2,0xe5,0xf9,0x7d,0xed,0xae,0xee,0xee,0xcc,0x4e,0x84,0xc6,0x88,0xe8,0x87,0x2e };
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

TEST_CASE("CFB1MCT256-ENCRYPT-74", "[CFB1][MCT][256][ENCRYPT][n74]") {
    const uint8_t KEY[] = { 0x5c,0x5d,0xf5,0x9a,0x8a,0xbe,0xad,0xf2,0xc0,0x1b,0xab,0x92,0x63,0xcf,0x54,0x10,0x25,0xf9,0x8d,0x61,0xdd,0x16,0x90,0xda,0xdc,0x3d,0xf9,0x0d,0x67,0xde,0xb8,0x36 };
    const uint8_t IV[] = { 0x26,0x5b,0x86,0xa7,0x33,0x6d,0x2c,0xb0,0xd6,0x49,0x68,0xb1,0x24,0xfa,0x5a,0xd2 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-75", "[CFB1][MCT][256][ENCRYPT][n75]") {
    const uint8_t KEY[] = { 0xbe,0x76,0x03,0x09,0xe3,0x67,0x3a,0x6f,0xa5,0x29,0x6f,0x90,0x22,0x53,0x59,0x23,0x55,0x17,0x90,0x18,0x69,0xaa,0x64,0x96,0xd7,0xf1,0xb8,0x4c,0x83,0xa2,0xfa,0x0a };
    const uint8_t IV[] = { 0x70,0xee,0x1d,0x79,0xb4,0xbc,0xf4,0x4c,0x0b,0xcc,0x41,0x41,0xe4,0x7c,0x42,0x3c };
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

TEST_CASE("CFB1MCT256-ENCRYPT-76", "[CFB1][MCT][256][ENCRYPT][n76]") {
    const uint8_t KEY[] = { 0xf2,0x53,0x90,0x60,0x2c,0xb0,0x47,0x43,0x97,0x34,0x3f,0xca,0x0f,0xf8,0xc9,0xac,0x15,0xd2,0x02,0xa6,0x97,0xb9,0xd4,0xae,0xb8,0xbc,0xf1,0xd1,0x79,0xc9,0xac,0x3a };
    const uint8_t IV[] = { 0x40,0xc5,0x92,0xbe,0xfe,0x13,0xb0,0x38,0x6f,0x4d,0x49,0x9d,0xfa,0x6b,0x56,0x30 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-77", "[CFB1][MCT][256][ENCRYPT][n77]") {
    const uint8_t KEY[] = { 0xaa,0x62,0xdb,0xb3,0x6e,0xfd,0x41,0x9b,0x8d,0x0d,0x73,0x2c,0x5e,0x59,0x06,0xdf,0x35,0x6a,0xad,0x8f,0xae,0x61,0x71,0xad,0x49,0x19,0x1e,0x8e,0x28,0x93,0xa4,0xde };
    const uint8_t IV[] = { 0x20,0xb8,0xaf,0x29,0x39,0xd8,0xa5,0x03,0xf1,0xa5,0xef,0x5f,0x51,0x5a,0x08,0xe4 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-78", "[CFB1][MCT][256][ENCRYPT][n78]") {
    const uint8_t KEY[] = { 0x24,0x9e,0x5e,0x1e,0xfc,0x30,0xbc,0x9d,0xcd,0x61,0x94,0x2a,0xda,0xed,0xd4,0x0b,0xa3,0xcd,0x72,0xaa,0xc8,0x8d,0x79,0xcc,0x68,0x39,0xc3,0xd9,0x17,0xae,0xf8,0x9a };
    const uint8_t IV[] = { 0x96,0xa7,0xdf,0x25,0x66,0xec,0x08,0x61,0x21,0x20,0xdd,0x57,0x3f,0x3d,0x5c,0x44 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-79", "[CFB1][MCT][256][ENCRYPT][n79]") {
    const uint8_t KEY[] = { 0x09,0x49,0xb8,0x4e,0x3d,0x1b,0xe4,0xfc,0x5f,0xde,0x9b,0xc1,0x14,0x11,0x7e,0x50,0x56,0xe7,0x0d,0x08,0x36,0xd5,0x5c,0x73,0xc2,0x6f,0xb4,0x3b,0xe6,0xf4,0xb3,0x11 };
    const uint8_t IV[] = { 0xf5,0x2a,0x7f,0xa2,0xfe,0x58,0x25,0xbf,0xaa,0x56,0x77,0xe2,0xf1,0x5a,0x4b,0x8b };
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

TEST_CASE("CFB1MCT256-ENCRYPT-80", "[CFB1][MCT][256][ENCRYPT][n80]") {
    const uint8_t KEY[] = { 0xed,0x5f,0x15,0xf9,0x07,0x70,0x36,0x0d,0x72,0x9e,0x5c,0x70,0x2c,0xa3,0xe7,0x7d,0x33,0x4b,0xe5,0x65,0x3b,0x04,0x43,0x5e,0xff,0x87,0x9f,0x71,0x15,0x2e,0x9e,0x93 };
    const uint8_t IV[] = { 0x65,0xac,0xe8,0x6d,0x0d,0xd1,0x1f,0x2d,0x3d,0xe8,0x2b,0x4a,0xf3,0xda,0x2d,0x82 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-81", "[CFB1][MCT][256][ENCRYPT][n81]") {
    const uint8_t KEY[] = { 0x5a,0x42,0x94,0x96,0x40,0x2d,0xfe,0x4a,0x2d,0xf2,0x22,0xa6,0x1f,0x36,0x0b,0xa1,0x14,0x6f,0x96,0x66,0x41,0xda,0xbe,0x8f,0x82,0x75,0xc2,0xbf,0x26,0xf1,0x3b,0xaa };
    const uint8_t IV[] = { 0x27,0x24,0x73,0x03,0x7a,0xde,0xfd,0xd1,0x7d,0xf2,0x5d,0xce,0x33,0xdf,0xa5,0x39 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-82", "[CFB1][MCT][256][ENCRYPT][n82]") {
    const uint8_t KEY[] = { 0xf9,0xfb,0xf4,0x5a,0xcc,0xf6,0xdc,0xbc,0x34,0xa3,0xc7,0x8f,0x7a,0x01,0xdf,0x90,0xe7,0x53,0xeb,0x0d,0x96,0x65,0x11,0xa1,0x06,0xa6,0xb6,0x20,0xd5,0x89,0x65,0xfc };
    const uint8_t IV[] = { 0xf3,0x3c,0x7d,0x6b,0xd7,0xbf,0xaf,0x2e,0x84,0xd3,0x74,0x9f,0xf3,0x78,0x5e,0x56 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-83", "[CFB1][MCT][256][ENCRYPT][n83]") {
    const uint8_t KEY[] = { 0x29,0x47,0x38,0x5b,0x45,0x05,0x3e,0x9c,0x26,0x51,0xa1,0x0e,0x9d,0x09,0x98,0x2c,0xbe,0x60,0x4d,0xb7,0x93,0xd6,0xc7,0xc8,0x53,0xeb,0x66,0xe4,0xa9,0x86,0x7c,0x4f };
    const uint8_t IV[] = { 0x59,0x33,0xa6,0xba,0x05,0xb3,0xd6,0x69,0x55,0x4d,0xd0,0xc4,0x7c,0x0f,0x19,0xb3 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-84", "[CFB1][MCT][256][ENCRYPT][n84]") {
    const uint8_t KEY[] = { 0xd6,0x60,0xb1,0x51,0x7d,0x0c,0x85,0xfa,0xca,0x89,0x42,0xc7,0x69,0x48,0xa0,0xba,0xae,0x9c,0x45,0x37,0x0f,0xe2,0xa9,0x4a,0xc9,0x0a,0xba,0x71,0x77,0x96,0x1d,0x2c };
    const uint8_t IV[] = { 0x10,0xfc,0x08,0x80,0x9c,0x34,0x6e,0x82,0x9a,0xe1,0xdc,0x95,0xde,0x10,0x61,0x63 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-85", "[CFB1][MCT][256][ENCRYPT][n85]") {
    const uint8_t KEY[] = { 0x1e,0xe9,0xd7,0xb8,0xec,0x3a,0x9f,0xdc,0x27,0x14,0x0f,0xa0,0x23,0xd7,0x31,0x3a,0x72,0x9c,0x67,0x55,0x9a,0xe2,0xa5,0x98,0x1d,0xa4,0xf5,0xc4,0x3a,0x01,0x38,0x3b };
    const uint8_t IV[] = { 0xdc,0x00,0x22,0x62,0x95,0x00,0x0c,0xd2,0xd4,0xae,0x4f,0xb5,0x4d,0x97,0x25,0x17 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-86", "[CFB1][MCT][256][ENCRYPT][n86]") {
    const uint8_t KEY[] = { 0x5f,0xed,0x8e,0xaf,0xb2,0xf4,0x92,0xe4,0xd4,0x6e,0x6c,0xf2,0x94,0x1f,0xe8,0x79,0x79,0x41,0x90,0x81,0x3d,0xf8,0x44,0x71,0xf4,0xa9,0x14,0x63,0x92,0xf6,0xe5,0x1f };
    const uint8_t IV[] = { 0x0b,0xdd,0xf7,0xd4,0xa7,0x1a,0xe1,0xe9,0xe9,0x0d,0xe1,0xa7,0xa8,0xf7,0xdd,0x24 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-87", "[CFB1][MCT][256][ENCRYPT][n87]") {
    const uint8_t KEY[] = { 0x88,0xed,0x61,0x67,0x3e,0x97,0xa1,0x5f,0x15,0xcb,0xa8,0x48,0x7a,0x6a,0xfe,0x51,0xe1,0x03,0x58,0x01,0x4c,0x5f,0x73,0xc6,0x9c,0x50,0x1c,0xf4,0xb0,0x4d,0x34,0x13 };
    const uint8_t IV[] = { 0x98,0x42,0xc8,0x80,0x71,0xa7,0x37,0xb7,0x68,0xf9,0x08,0x97,0x22,0xbb,0xd1,0x0c };
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

TEST_CASE("CFB1MCT256-ENCRYPT-88", "[CFB1][MCT][256][ENCRYPT][n88]") {
    const uint8_t KEY[] = { 0x6e,0x23,0xac,0x38,0x74,0xc1,0x3a,0xf6,0xf8,0xf0,0x90,0x85,0x7b,0xd7,0x7e,0xa7,0xa9,0xf6,0xde,0x71,0x27,0x5c,0x5f,0xb9,0x7a,0x97,0x97,0xea,0x93,0xf3,0x6e,0x62 };
    const uint8_t IV[] = { 0x48,0xf5,0x86,0x70,0x6b,0x03,0x2c,0x7f,0xe6,0xc7,0x8b,0x1e,0x23,0xbe,0x5a,0x71 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-89", "[CFB1][MCT][256][ENCRYPT][n89]") {
    const uint8_t KEY[] = { 0xf2,0xe4,0xee,0xb4,0x1c,0x1e,0x0c,0x72,0x3d,0xb4,0x50,0x3e,0xf2,0x9e,0x6d,0x09,0x04,0x7f,0x7b,0xd9,0xfa,0x57,0xe6,0xac,0xac,0x5b,0x26,0xf3,0x0e,0x33,0x17,0x8a };
    const uint8_t IV[] = { 0xad,0x89,0xa5,0xa8,0xdd,0x0b,0xb9,0x15,0xd6,0xcc,0xb1,0x19,0x9d,0xc0,0x79,0xe8 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-90", "[CFB1][MCT][256][ENCRYPT][n90]") {
    const uint8_t KEY[] = { 0x42,0x6f,0x99,0xbd,0xca,0x55,0xcd,0x2b,0x43,0x63,0x2d,0xea,0x9e,0x15,0xee,0x13,0xc0,0xdb,0x1b,0x2c,0xc8,0x8a,0xe1,0xf6,0xbc,0xc2,0x4c,0x55,0x77,0x1c,0x20,0xc7 };
    const uint8_t IV[] = { 0xc4,0xa4,0x60,0xf5,0x32,0xdd,0x07,0x5a,0x10,0x99,0x6a,0xa6,0x79,0x2f,0x37,0x4d };
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

TEST_CASE("CFB1MCT256-ENCRYPT-91", "[CFB1][MCT][256][ENCRYPT][n91]") {
    const uint8_t KEY[] = { 0x90,0x62,0x97,0x0d,0x97,0xa8,0x96,0x72,0xd6,0xba,0xda,0x91,0x29,0x45,0x7b,0x29,0x5b,0xe5,0x01,0x42,0x9d,0x07,0x7d,0x87,0xbb,0x02,0xe5,0xbf,0x22,0x11,0xe6,0x27 };
    const uint8_t IV[] = { 0x9b,0x3e,0x1a,0x6e,0x55,0x8d,0x9c,0x71,0x07,0xc0,0xa9,0xea,0x55,0x0d,0xc6,0xe0 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-92", "[CFB1][MCT][256][ENCRYPT][n92]") {
    const uint8_t KEY[] = { 0x5d,0x69,0x87,0x28,0xfc,0x1a,0x0d,0x5b,0x29,0x0d,0x52,0x70,0x63,0xce,0xea,0xe8,0x7e,0xeb,0xe9,0x51,0x22,0xb2,0x04,0xff,0xb9,0xbd,0xa2,0x71,0x04,0xd3,0xd6,0xdc };
    const uint8_t IV[] = { 0x25,0x0e,0xe8,0x13,0xbf,0xb5,0x79,0x78,0x02,0xbf,0x47,0xce,0x26,0xc2,0x30,0xfb };
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

TEST_CASE("CFB1MCT256-ENCRYPT-93", "[CFB1][MCT][256][ENCRYPT][n93]") {
    const uint8_t KEY[] = { 0x2c,0x1a,0xbb,0x14,0xcf,0xac,0x52,0xb0,0x80,0x1b,0xee,0x66,0xd1,0x1e,0x6d,0x6e,0xd6,0x58,0xb2,0x45,0x4e,0x0e,0x41,0x1b,0xd0,0x2f,0x52,0x37,0x2a,0xf5,0xe2,0x38 };
    const uint8_t IV[] = { 0xa8,0xb3,0x5b,0x14,0x6c,0xbc,0x45,0xe4,0x69,0x92,0xf0,0x46,0x2e,0x26,0x34,0xe4 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-94", "[CFB1][MCT][256][ENCRYPT][n94]") {
    const uint8_t KEY[] = { 0x98,0xdb,0x56,0x04,0xa5,0xd4,0x02,0x33,0x0a,0xa9,0xd3,0x09,0xc3,0x78,0x35,0x5f,0x44,0x52,0xba,0x4d,0x03,0x8b,0x22,0xf0,0x4a,0xa4,0xbb,0xdc,0xea,0xa9,0xcf,0x4a };
    const uint8_t IV[] = { 0x92,0x0a,0x08,0x08,0x4d,0x85,0x63,0xeb,0x9a,0x8b,0xe9,0xeb,0xc0,0x5c,0x2d,0x72 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-95", "[CFB1][MCT][256][ENCRYPT][n95]") {
    const uint8_t KEY[] = { 0xa5,0x34,0x7b,0x5e,0xe1,0x76,0x55,0x09,0x85,0x58,0xba,0xe7,0xbb,0xed,0x84,0x44,0x76,0xe9,0x97,0xe4,0xb0,0xe4,0xb4,0xcf,0x59,0x56,0x00,0xea,0x1c,0xfc,0xe6,0xee };
    const uint8_t IV[] = { 0x32,0xbb,0x2d,0xa9,0xb3,0x6f,0x96,0x3f,0x13,0xf2,0xbb,0x36,0xf6,0x55,0x29,0xa4 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-96", "[CFB1][MCT][256][ENCRYPT][n96]") {
    const uint8_t KEY[] = { 0xd4,0x61,0x1b,0x3c,0x2e,0xeb,0x1c,0x13,0x83,0x59,0x5d,0x8f,0xf1,0xc0,0xad,0x6f,0x0b,0x77,0xc4,0xe4,0xfb,0xcb,0x9f,0xca,0x0c,0xb2,0x58,0xb4,0xaa,0x98,0x89,0xe9 };
    const uint8_t IV[] = { 0x7d,0x9e,0x53,0x00,0x4b,0x2f,0x2b,0x05,0x55,0xe4,0x58,0x5e,0xb6,0x64,0x6f,0x07 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-97", "[CFB1][MCT][256][ENCRYPT][n97]") {
    const uint8_t KEY[] = { 0x53,0xe5,0xab,0x83,0xc8,0xd9,0x0b,0x78,0xa3,0x6a,0x27,0x73,0x53,0x08,0x7d,0x60,0x40,0x63,0xee,0x7c,0xfa,0xf0,0xc0,0x14,0xf2,0xdf,0x4f,0x3d,0x7b,0xd3,0x35,0xc1 };
    const uint8_t IV[] = { 0x4b,0x14,0x2a,0x98,0x01,0x3b,0x5f,0xde,0xfe,0x6d,0x17,0x89,0xd1,0x4b,0xbc,0x28 };
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

TEST_CASE("CFB1MCT256-ENCRYPT-98", "[CFB1][MCT][256][ENCRYPT][n98]") {
    const uint8_t KEY[] = { 0xda,0xa1,0xe4,0x5a,0x4d,0x05,0xd6,0xda,0x6d,0x25,0x93,0x60,0x95,0x3f,0xdb,0xcb,0x76,0x5c,0xeb,0x61,0x11,0x78,0xd4,0xff,0x7b,0x69,0x87,0x3b,0xd5,0x34,0x11,0x0e };
    const uint8_t IV[] = { 0x36,0x3f,0x05,0x1d,0xeb,0x88,0x14,0xeb,0x89,0xb6,0xc8,0x06,0xae,0xe7,0x24,0xcf };
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

TEST_CASE("CFB1MCT256-ENCRYPT-99", "[CFB1][MCT][256][ENCRYPT][n99]") {
    const uint8_t KEY[] = { 0x52,0x75,0xa7,0x1a,0xf3,0x5b,0xda,0x48,0xeb,0x79,0xc3,0xc6,0x42,0x14,0x69,0x0e,0x6c,0x6b,0x22,0x91,0xae,0x21,0x7d,0xa1,0x66,0x37,0xe3,0x00,0xec,0x6b,0x75,0x88 };
    const uint8_t IV[] = { 0x1a,0x37,0xc9,0xf0,0xbf,0x59,0xa9,0x5e,0x1d,0x5e,0x64,0x3b,0x39,0x5f,0x64,0x86 };
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

TEST_CASE("CFB1MCT256-DECRYPT-0", "[CFB1][MCT][256][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0xa5,0xd1,0xe8,0xc1,0x0a,0x20,0xbd,0x3b,0xef,0xb9,0x59,0x72,0x69,0x2c,0x9d,0x13,0x82,0x2b,0xff,0x09,0x8c,0x91,0x82,0x9d,0xb5,0xa4,0xe6,0xe2,0xdb,0x97,0x1b,0x50 };
    const uint8_t IV[] = { 0x98,0x0c,0x24,0xad,0x0f,0xa1,0xb4,0x51,0x6b,0xfe,0x8e,0x35,0xab,0xb3,0x4f,0x8f };
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

TEST_CASE("CFB1MCT256-DECRYPT-1", "[CFB1][MCT][256][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0x0e,0x07,0xc9,0xc3,0x8b,0x2c,0x41,0x34,0xd1,0xea,0x50,0x4f,0x08,0x8e,0x39,0x7d,0x9c,0x56,0x24,0x43,0x38,0x35,0x4d,0xd2,0xbf,0x92,0xa3,0x4b,0xb6,0x74,0x2f,0xe6 };
    const uint8_t IV[] = { 0x1e,0x7d,0xdb,0x4a,0xb4,0xa4,0xcf,0x4f,0x0a,0x36,0x45,0xa9,0x6d,0xe3,0x34,0xb6 };
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

TEST_CASE("CFB1MCT256-DECRYPT-2", "[CFB1][MCT][256][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0xac,0x2b,0x71,0xd7,0xc4,0x3d,0x25,0x98,0xfe,0x64,0x47,0x96,0x01,0x07,0xf7,0xa9,0x40,0xdb,0x12,0xaa,0x27,0xa4,0xef,0xca,0x3d,0xe7,0x09,0x56,0xf4,0x02,0x0a,0x65 };
    const uint8_t IV[] = { 0xdc,0x8d,0x36,0xe9,0x1f,0x91,0xa2,0x18,0x82,0x75,0xaa,0x1d,0x42,0x76,0x25,0x83 };
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

TEST_CASE("CFB1MCT256-DECRYPT-3", "[CFB1][MCT][256][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0x97,0x89,0x87,0x70,0x14,0x6b,0xf1,0x31,0xd4,0x59,0x89,0xe4,0x9c,0x45,0xfd,0xed,0x26,0x8f,0xa0,0xa7,0x55,0xac,0x97,0x3c,0xbc,0x2a,0xe0,0x26,0x76,0x37,0xc7,0x62 };
    const uint8_t IV[] = { 0x66,0x54,0xb2,0x0d,0x72,0x08,0x78,0xf6,0x81,0xcd,0xe9,0x70,0x82,0x35,0xcd,0x07 };
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

TEST_CASE("CFB1MCT256-DECRYPT-4", "[CFB1][MCT][256][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0xf9,0x05,0x3e,0x73,0x95,0x2f,0x99,0x8d,0x7b,0x07,0xa8,0x61,0x02,0xec,0xab,0xa4,0x06,0x86,0x2f,0xd4,0xbd,0xe2,0xd6,0xdf,0x5f,0x9e,0x56,0x48,0xc3,0xf7,0x3b,0x99 };
    const uint8_t IV[] = { 0x20,0x09,0x8f,0x73,0xe8,0x4e,0x41,0xe3,0xe3,0xb4,0xb6,0x6e,0xb5,0xc0,0xfc,0xfb };
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

TEST_CASE("CFB1MCT256-DECRYPT-5", "[CFB1][MCT][256][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0xe8,0x53,0xde,0x9a,0x14,0x9e,0x84,0x7a,0x85,0x1e,0x6c,0xd6,0xdd,0xc0,0xa1,0xa8,0xef,0x3a,0xfa,0xf0,0x23,0x77,0x70,0x10,0x4d,0xc1,0x6c,0x82,0x38,0xbd,0x05,0x79 };
    const uint8_t IV[] = { 0xe9,0xbc,0xd5,0x24,0x9e,0x95,0xa6,0xcf,0x12,0x5f,0x3a,0xca,0xfb,0x4a,0x3e,0xe0 };
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

TEST_CASE("CFB1MCT256-DECRYPT-6", "[CFB1][MCT][256][DECRYPT][n6]") {
    const uint8_t KEY[] = { 0x2e,0xb6,0xd3,0x71,0x54,0xe2,0x65,0x7e,0xac,0xa1,0xe4,0x99,0x6a,0x16,0x45,0x62,0x2b,0xab,0xfb,0x0b,0xac,0xcf,0xf8,0xbf,0xbb,0x81,0xe1,0x16,0xaf,0x37,0xb1,0x85 };
    const uint8_t IV[] = { 0xc4,0x91,0x01,0xfb,0x8f,0xb8,0x88,0xaf,0xf6,0x40,0x8d,0x94,0x97,0x8a,0xb4,0xfc };
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

TEST_CASE("CFB1MCT256-DECRYPT-7", "[CFB1][MCT][256][DECRYPT][n7]") {
    const uint8_t KEY[] = { 0xd7,0x80,0x3b,0xaf,0x6f,0xa6,0x53,0xaf,0x6b,0x41,0xd3,0x19,0xdb,0x47,0xf1,0xaa,0x89,0x2a,0x7e,0x76,0x58,0xe6,0xb4,0x12,0x1f,0x0f,0x6f,0xc0,0xab,0x5c,0x91,0xf6 };
    const uint8_t IV[] = { 0xa2,0x81,0x85,0x7d,0xf4,0x29,0x4c,0xad,0xa4,0x8e,0x8e,0xd6,0x04,0x6b,0x20,0x73 };
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

TEST_CASE("CFB1MCT256-DECRYPT-8", "[CFB1][MCT][256][DECRYPT][n8]") {
    const uint8_t KEY[] = { 0xcf,0xa2,0xc0,0x0a,0x15,0x99,0x72,0x6f,0xd5,0x93,0x5f,0x9c,0x33,0x9f,0xbf,0xa3,0x61,0x7b,0xda,0x41,0x87,0xb5,0x24,0x7a,0xf2,0xe1,0x6d,0xfc,0xa3,0x2c,0x48,0x8f };
    const uint8_t IV[] = { 0xe8,0x51,0xa4,0x37,0xdf,0x53,0x90,0x68,0xed,0xee,0x02,0x3c,0x08,0x70,0xd9,0x79 };
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

TEST_CASE("CFB1MCT256-DECRYPT-9", "[CFB1][MCT][256][DECRYPT][n9]") {
    const uint8_t KEY[] = { 0xc7,0xeb,0x43,0x15,0xe4,0x15,0x5e,0x4b,0xf3,0x9e,0x55,0xda,0x24,0x22,0xf1,0xd9,0xa2,0xd7,0x50,0x4f,0x00,0xb4,0xec,0xb3,0x35,0x53,0x5d,0xf3,0xbf,0x37,0xb0,0xa9 };
    const uint8_t IV[] = { 0xc3,0xac,0x8a,0x0e,0x87,0x01,0xc8,0xc9,0xc7,0xb2,0x30,0x0f,0x1c,0x1b,0xf8,0x26 };
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

TEST_CASE("CFB1MCT256-DECRYPT-10", "[CFB1][MCT][256][DECRYPT][n10]") {
    const uint8_t KEY[] = { 0xe8,0xb7,0x70,0x57,0xe4,0x89,0x7d,0x9f,0xa7,0xa7,0x43,0xbc,0x6b,0x3d,0xb0,0xc9,0xe2,0x00,0xce,0x13,0x66,0x40,0x72,0x2d,0x6b,0x67,0x21,0x0a,0x4c,0xff,0xd2,0x61 };
    const uint8_t IV[] = { 0x40,0xd7,0x9e,0x5c,0x66,0xf4,0x9e,0x9e,0x5e,0x34,0x7c,0xf9,0xf3,0xc8,0x62,0xc8 };
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

TEST_CASE("CFB1MCT256-DECRYPT-11", "[CFB1][MCT][256][DECRYPT][n11]") {
    const uint8_t KEY[] = { 0x98,0xe0,0x31,0x3b,0xeb,0xdf,0x1d,0x19,0x8e,0x9c,0x0f,0xb6,0xaa,0x34,0x08,0x07,0x5f,0x91,0x15,0xae,0x8a,0x3e,0x20,0xea,0xa3,0x94,0x03,0x5a,0x0c,0xad,0x7e,0x54 };
    const uint8_t IV[] = { 0xbd,0x91,0xdb,0xbd,0xec,0x7e,0x52,0xc7,0xc8,0xf3,0x22,0x50,0x40,0x52,0xac,0x35 };
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

TEST_CASE("CFB1MCT256-DECRYPT-12", "[CFB1][MCT][256][DECRYPT][n12]") {
    const uint8_t KEY[] = { 0xc2,0x89,0xc7,0xa8,0x6b,0x6b,0x64,0x97,0x21,0x11,0x53,0x2d,0x5d,0x00,0x4c,0xe6,0x9f,0x21,0xf5,0x04,0x01,0x35,0x52,0x62,0xb0,0x6d,0x9e,0x57,0x46,0xfb,0xb7,0xbc };
    const uint8_t IV[] = { 0xc0,0xb0,0xe0,0xaa,0x8b,0x0b,0x72,0x88,0x13,0xf9,0x9d,0x0d,0x4a,0x56,0xc9,0xe8 };
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

TEST_CASE("CFB1MCT256-DECRYPT-13", "[CFB1][MCT][256][DECRYPT][n13]") {
    const uint8_t KEY[] = { 0x17,0x76,0xd3,0x5b,0x90,0xd1,0x0c,0x6d,0x16,0x76,0xf9,0x40,0xbf,0x8e,0x71,0x42,0x9f,0x00,0x7d,0x72,0x82,0x0a,0xa8,0x9b,0xfe,0xab,0x17,0xc0,0xea,0x85,0xc7,0x69 };
    const uint8_t IV[] = { 0x00,0x21,0x88,0x76,0x83,0x3f,0xfa,0xf9,0x4e,0xc6,0x89,0x97,0xac,0x7e,0x70,0xd5 };
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

TEST_CASE("CFB1MCT256-DECRYPT-14", "[CFB1][MCT][256][DECRYPT][n14]") {
    const uint8_t KEY[] = { 0x53,0x39,0x03,0x02,0x41,0xf9,0xff,0xc1,0x9e,0x43,0x40,0x57,0x96,0x67,0x65,0x10,0xa6,0xcd,0xfa,0x27,0x34,0xe8,0x2d,0x68,0xcf,0xa1,0xde,0x41,0xea,0x86,0x0a,0x58 };
    const uint8_t IV[] = { 0x39,0xcd,0x87,0x55,0xb6,0xe2,0x85,0xf3,0x31,0x0a,0xc9,0x81,0x00,0x03,0xcd,0x31 };
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

TEST_CASE("CFB1MCT256-DECRYPT-15", "[CFB1][MCT][256][DECRYPT][n15]") {
    const uint8_t KEY[] = { 0x94,0x3d,0x17,0x02,0x05,0x4a,0x03,0x81,0xc3,0x60,0xcd,0xb4,0x4e,0xe5,0xe5,0xe8,0x51,0x16,0x06,0x7b,0xb8,0x73,0x99,0x0c,0xcd,0xcb,0xa8,0x36,0x00,0xa2,0x6a,0xfe };
    const uint8_t IV[] = { 0xf7,0xdb,0xfc,0x5c,0x8c,0x9b,0xb4,0x64,0x02,0x6a,0x76,0x77,0xea,0x24,0x60,0xa6 };
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

TEST_CASE("CFB1MCT256-DECRYPT-16", "[CFB1][MCT][256][DECRYPT][n16]") {
    const uint8_t KEY[] = { 0xa5,0x9c,0xe7,0x0d,0x91,0x99,0x51,0x6d,0x8c,0x15,0x96,0xa3,0x14,0xbc,0xe4,0x50,0xd7,0xdb,0x57,0xce,0x81,0x2a,0x8e,0x32,0xc3,0x5b,0x00,0x78,0xb4,0xe1,0xbd,0x93 };
    const uint8_t IV[] = { 0x86,0xcd,0x51,0xb5,0x39,0x59,0x17,0x3e,0x0e,0x90,0xa8,0x4e,0xb4,0x43,0xd7,0x6d };
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

TEST_CASE("CFB1MCT256-DECRYPT-17", "[CFB1][MCT][256][DECRYPT][n17]") {
    const uint8_t KEY[] = { 0x44,0x48,0x32,0x70,0x33,0x7e,0xf5,0x56,0x73,0xd9,0x78,0x8d,0x05,0x57,0x2c,0x4c,0x0b,0x31,0x61,0x57,0xac,0x31,0x0f,0x8a,0x3d,0x20,0x51,0x2c,0xeb,0x0a,0x79,0xdb };
    const uint8_t IV[] = { 0xdc,0xea,0x36,0x99,0x2d,0x1b,0x81,0xb8,0xfe,0x7b,0x51,0x54,0x5f,0xeb,0xc4,0x48 };
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

TEST_CASE("CFB1MCT256-DECRYPT-18", "[CFB1][MCT][256][DECRYPT][n18]") {
    const uint8_t KEY[] = { 0x58,0xa1,0xe1,0xed,0xcb,0x95,0xe0,0x2a,0x3f,0xe9,0x32,0x47,0x1a,0x57,0x5d,0x71,0x35,0x00,0x99,0xfc,0x6c,0x7e,0x3e,0x91,0x36,0xf7,0x34,0x6e,0x96,0xae,0xf7,0x08 };
    const uint8_t IV[] = { 0x3e,0x31,0xf8,0xab,0xc0,0x4f,0x31,0x1b,0x0b,0xd7,0x65,0x42,0x7d,0xa4,0x8e,0xd3 };
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

TEST_CASE("CFB1MCT256-DECRYPT-19", "[CFB1][MCT][256][DECRYPT][n19]") {
    const uint8_t KEY[] = { 0x82,0x97,0x79,0x9d,0xac,0x9b,0xb1,0x04,0x25,0x54,0xff,0xc1,0x39,0x61,0x7f,0xad,0xff,0xa2,0xe3,0x35,0x0c,0xb2,0x4b,0xdd,0x76,0xc1,0x8a,0x84,0x63,0x77,0xc2,0x8c };
    const uint8_t IV[] = { 0xca,0xa2,0x7a,0xc9,0x60,0xcc,0x75,0x4c,0x40,0x36,0xbe,0xea,0xf5,0xd9,0x35,0x84 };
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

TEST_CASE("CFB1MCT256-DECRYPT-20", "[CFB1][MCT][256][DECRYPT][n20]") {
    const uint8_t KEY[] = { 0x98,0x17,0x9a,0x6e,0x86,0x96,0x53,0xd7,0x67,0x86,0x24,0x24,0x18,0x70,0xdf,0xb4,0xab,0x4d,0x26,0x86,0xea,0x39,0x7d,0x91,0xbb,0x7a,0xd7,0xf8,0x02,0x27,0x4b,0xc9 };
    const uint8_t IV[] = { 0x54,0xef,0xc5,0xb3,0xe6,0x8b,0x36,0x4c,0xcd,0xbb,0x5d,0x7c,0x61,0x50,0x89,0x45 };
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

TEST_CASE("CFB1MCT256-DECRYPT-21", "[CFB1][MCT][256][DECRYPT][n21]") {
    const uint8_t KEY[] = { 0x15,0x43,0xd3,0xa2,0x2c,0xb5,0x6f,0x05,0x23,0xf8,0x86,0x4f,0x65,0x7d,0xf0,0xe8,0x34,0xc6,0xf5,0x7d,0x36,0x9d,0x5d,0x92,0xe4,0xdd,0x12,0x5d,0xa2,0xa8,0xf7,0xf1 };
    const uint8_t IV[] = { 0x9f,0x8b,0xd3,0xfb,0xdc,0xa4,0x20,0x03,0x5f,0xa7,0xc5,0xa5,0xa0,0x8f,0xbc,0x38 };
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

TEST_CASE("CFB1MCT256-DECRYPT-22", "[CFB1][MCT][256][DECRYPT][n22]") {
    const uint8_t KEY[] = { 0x00,0x76,0xd5,0xca,0x84,0x01,0x31,0x20,0x82,0x4e,0xad,0x1a,0xbd,0x99,0x28,0x21,0xe6,0xdd,0x78,0x3e,0x20,0xda,0x7f,0x70,0x4b,0x19,0x7c,0x59,0x42,0x89,0xef,0x96 };
    const uint8_t IV[] = { 0xd2,0x1b,0x8d,0x43,0x16,0x47,0x22,0xe2,0xaf,0xc4,0x6e,0x04,0xe0,0x21,0x18,0x67 };
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

TEST_CASE("CFB1MCT256-DECRYPT-23", "[CFB1][MCT][256][DECRYPT][n23]") {
    const uint8_t KEY[] = { 0x84,0x04,0xa7,0xf0,0xfe,0xda,0x29,0xad,0x33,0x4f,0x37,0xc1,0x00,0x38,0xc4,0xba,0x95,0x8a,0xad,0x0b,0xb1,0x2d,0x86,0xf0,0x28,0xd0,0xea,0xd9,0xd5,0xc5,0x4b,0x0d };
    const uint8_t IV[] = { 0x73,0x57,0xd5,0x35,0x91,0xf7,0xf9,0x80,0x63,0xc9,0x96,0x80,0x97,0x4c,0xa4,0x9b };
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

TEST_CASE("CFB1MCT256-DECRYPT-24", "[CFB1][MCT][256][DECRYPT][n24]") {
    const uint8_t KEY[] = { 0x86,0xdc,0x5b,0x73,0xaa,0x13,0xa8,0x4f,0x22,0x7a,0x61,0x19,0x21,0xce,0xde,0x3a,0x96,0x10,0x4c,0x3d,0xee,0x8b,0x99,0xe9,0x64,0x4b,0xf5,0x36,0x6e,0x3a,0x00,0x1f };
    const uint8_t IV[] = { 0x03,0x9a,0xe1,0x36,0x5f,0xa6,0x1f,0x19,0x4c,0x9b,0x1f,0xef,0xbb,0xff,0x4b,0x12 };
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

TEST_CASE("CFB1MCT256-DECRYPT-25", "[CFB1][MCT][256][DECRYPT][n25]") {
    const uint8_t KEY[] = { 0x43,0x85,0x90,0xf4,0xff,0xdc,0xfc,0xbb,0xe3,0x3f,0xc6,0xa3,0x5c,0x11,0x83,0xad,0xc5,0xe3,0x22,0xf1,0xb7,0x2b,0x79,0xc6,0xef,0x8a,0xbd,0xcb,0xf9,0xec,0x43,0x67 };
    const uint8_t IV[] = { 0x53,0xf3,0x6e,0xcc,0x59,0xa0,0xe0,0x2f,0x8b,0xc1,0x48,0xfd,0x97,0xd6,0x43,0x78 };
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

TEST_CASE("CFB1MCT256-DECRYPT-26", "[CFB1][MCT][256][DECRYPT][n26]") {
    const uint8_t KEY[] = { 0x7f,0xa9,0x06,0x89,0xb2,0xd1,0xa0,0x88,0xeb,0xa5,0xc5,0x7e,0x5a,0xce,0x42,0x87,0x0d,0x29,0xea,0x47,0x17,0x48,0x4b,0x3a,0x3a,0x70,0x03,0x8c,0xfd,0x2c,0x26,0x14 };
    const uint8_t IV[] = { 0xc8,0xca,0xc8,0xb6,0xa0,0x63,0x32,0xfc,0xd5,0xfa,0xbe,0x47,0x04,0xc0,0x65,0x73 };
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

TEST_CASE("CFB1MCT256-DECRYPT-27", "[CFB1][MCT][256][DECRYPT][n27]") {
    const uint8_t KEY[] = { 0x2c,0x37,0x4a,0xcd,0x01,0x64,0x9d,0x2e,0x71,0x70,0x03,0x45,0xbb,0x62,0x9e,0x65,0xea,0x61,0x89,0x54,0xa1,0x1d,0xb1,0xe5,0x9d,0x44,0x45,0x45,0xd3,0x77,0x8d,0xca };
    const uint8_t IV[] = { 0xe7,0x48,0x63,0x13,0xb6,0x55,0xfa,0xdf,0xa7,0x34,0x46,0xc9,0x2e,0x5b,0xab,0xde };
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

TEST_CASE("CFB1MCT256-DECRYPT-28", "[CFB1][MCT][256][DECRYPT][n28]") {
    const uint8_t KEY[] = { 0x6a,0xfc,0x50,0x34,0x2a,0x00,0x68,0xda,0x23,0xd6,0x18,0x34,0xc2,0xaf,0x4c,0x47,0xa3,0x5d,0x80,0x70,0xde,0x66,0x64,0x80,0x14,0x0b,0x49,0xeb,0x94,0x06,0x15,0x43 };
    const uint8_t IV[] = { 0x49,0x3c,0x09,0x24,0x7f,0x7b,0xd5,0x65,0x89,0x4f,0x0c,0xae,0x47,0x71,0x98,0x89 };
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

TEST_CASE("CFB1MCT256-DECRYPT-29", "[CFB1][MCT][256][DECRYPT][n29]") {
    const uint8_t KEY[] = { 0x7a,0x70,0x4b,0x0b,0x63,0xdc,0x77,0x1d,0x36,0x71,0x8a,0xcd,0xbe,0x9b,0x0e,0x60,0x37,0x80,0x6e,0x20,0x84,0xf9,0x01,0x5c,0xcb,0xcb,0x9d,0xef,0xc8,0x3a,0xf5,0x16 };
    const uint8_t IV[] = { 0x94,0xdd,0xee,0x50,0x5a,0x9f,0x65,0xdc,0xdf,0xc0,0xd4,0x04,0x5c,0x3c,0xe0,0x55 };
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

TEST_CASE("CFB1MCT256-DECRYPT-30", "[CFB1][MCT][256][DECRYPT][n30]") {
    const uint8_t KEY[] = { 0x92,0xcd,0xc6,0x24,0x6d,0x20,0xbf,0x59,0xff,0xe9,0xae,0x8d,0x95,0x81,0x33,0x4c,0x78,0x68,0x70,0x1f,0x1e,0x30,0xec,0xdf,0xe6,0x10,0x4a,0xcb,0x58,0x65,0x49,0xa8 };
    const uint8_t IV[] = { 0x4f,0xe8,0x1e,0x3f,0x9a,0xc9,0xed,0x83,0x2d,0xdb,0xd7,0x24,0x90,0x5f,0xbc,0xbe };
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

TEST_CASE("CFB1MCT256-DECRYPT-31", "[CFB1][MCT][256][DECRYPT][n31]") {
    const uint8_t KEY[] = { 0x9c,0x7c,0x6d,0x47,0x70,0x55,0x96,0x23,0xfd,0x79,0x9d,0x93,0xef,0x4b,0x5d,0x76,0x62,0x76,0xa6,0x98,0x21,0x1b,0xbb,0x28,0x2b,0x79,0x85,0xf6,0x71,0x0b,0xc4,0xb3 };
    const uint8_t IV[] = { 0x1a,0x1e,0xd6,0x87,0x3f,0x2b,0x57,0xf7,0xcd,0x69,0xcf,0x3d,0x29,0x6e,0x8d,0x1b };
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

TEST_CASE("CFB1MCT256-DECRYPT-32", "[CFB1][MCT][256][DECRYPT][n32]") {
    const uint8_t KEY[] = { 0x50,0xaa,0x9a,0x93,0x9e,0xc2,0xdc,0xef,0xee,0xb1,0x35,0xd7,0x26,0xd3,0x15,0x73,0xed,0x19,0x25,0x1e,0x2b,0xf8,0xac,0x56,0x69,0xa4,0x24,0x3d,0x3c,0xd8,0x67,0x37 };
    const uint8_t IV[] = { 0x8f,0x6f,0x83,0x86,0x0a,0xe3,0x17,0x7e,0x42,0xdd,0xa1,0xcb,0x4d,0xd3,0xa3,0x84 };
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

TEST_CASE("CFB1MCT256-DECRYPT-33", "[CFB1][MCT][256][DECRYPT][n33]") {
    const uint8_t KEY[] = { 0x69,0x49,0x2e,0x70,0xc1,0xba,0x1b,0x6d,0x56,0x4d,0x9e,0x94,0x03,0x3e,0x6b,0x29,0x54,0xcb,0x97,0x05,0xd6,0x85,0x74,0xec,0x0e,0x02,0x2c,0xfa,0x9b,0x3a,0x97,0x22 };
    const uint8_t IV[] = { 0xb9,0xd2,0xb2,0x1b,0xfd,0x7d,0xd8,0xba,0x67,0xa6,0x08,0xc7,0xa7,0xe2,0xf0,0x15 };
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

TEST_CASE("CFB1MCT256-DECRYPT-34", "[CFB1][MCT][256][DECRYPT][n34]") {
    const uint8_t KEY[] = { 0x47,0x94,0x06,0xc8,0x88,0xcd,0x32,0x17,0xb7,0x65,0xcb,0xde,0xca,0xd4,0x36,0xe9,0xca,0x71,0x14,0x11,0x36,0x79,0xec,0x03,0x8e,0xfe,0xf3,0xc5,0xd4,0xbc,0xee,0x89 };
    const uint8_t IV[] = { 0x9e,0xba,0x83,0x14,0xe0,0xfc,0x98,0xef,0x80,0xfc,0xdf,0x3f,0x4f,0x86,0x79,0xab };
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

TEST_CASE("CFB1MCT256-DECRYPT-35", "[CFB1][MCT][256][DECRYPT][n35]") {
    const uint8_t KEY[] = { 0x62,0xf2,0x39,0x99,0x3d,0x98,0x79,0xa2,0xe5,0x5c,0xce,0x1b,0x3d,0x2c,0xff,0x18,0x12,0xc8,0x41,0x44,0xb1,0x82,0xbe,0xc5,0x5b,0x33,0x4e,0xfb,0x9c,0x09,0xd2,0xc2 };
    const uint8_t IV[] = { 0xd8,0xb9,0x55,0x55,0x87,0xfb,0x52,0xc6,0xd5,0xcd,0xbd,0x3e,0x48,0xb5,0x3c,0x4b };
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

TEST_CASE("CFB1MCT256-DECRYPT-36", "[CFB1][MCT][256][DECRYPT][n36]") {
    const uint8_t KEY[] = { 0xb1,0xce,0x39,0x72,0x13,0xff,0xad,0x63,0x8f,0xfc,0xea,0x0a,0x94,0x9e,0x9c,0xe0,0x1e,0x4e,0xe4,0x6e,0x0d,0xb5,0x65,0xe3,0x8e,0x24,0x7e,0xe3,0x15,0xfa,0x92,0x16 };
    const uint8_t IV[] = { 0x0c,0x86,0xa5,0x2a,0xbc,0x37,0xdb,0x26,0xd5,0x17,0x30,0x18,0x89,0xf3,0x40,0xd4 };
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

TEST_CASE("CFB1MCT256-DECRYPT-37", "[CFB1][MCT][256][DECRYPT][n37]") {
    const uint8_t KEY[] = { 0x9b,0x64,0x8e,0x18,0xef,0xfa,0x81,0x15,0x51,0xe3,0xf3,0xc9,0x18,0x81,0xd5,0xb2,0x5c,0xc0,0xbe,0xc3,0xef,0x7a,0xc2,0x49,0xf3,0xd3,0xfa,0x3a,0x4b,0x40,0x4d,0x17 };
    const uint8_t IV[] = { 0x42,0x8e,0x5a,0xad,0xe2,0xcf,0xa7,0xaa,0x7d,0xf7,0x84,0xd9,0x5e,0xba,0xdf,0x01 };
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

TEST_CASE("CFB1MCT256-DECRYPT-38", "[CFB1][MCT][256][DECRYPT][n38]") {
    const uint8_t KEY[] = { 0xaf,0x84,0xc6,0x07,0x43,0x01,0x95,0x66,0x1a,0x32,0xc1,0x13,0xaa,0xa8,0xc9,0x83,0x3f,0x6e,0x07,0xa2,0x91,0x72,0x33,0xb7,0x61,0xa0,0x77,0x50,0xef,0xfe,0x39,0x95 };
    const uint8_t IV[] = { 0x63,0xae,0xb9,0x61,0x7e,0x08,0xf1,0xfe,0x92,0x73,0x8d,0x6a,0xa4,0xbe,0x74,0x82 };
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

TEST_CASE("CFB1MCT256-DECRYPT-39", "[CFB1][MCT][256][DECRYPT][n39]") {
    const uint8_t KEY[] = { 0xbe,0x08,0x3a,0xe2,0x65,0xb8,0x6f,0x01,0x89,0x58,0xec,0xb9,0x50,0xcd,0x7c,0x30,0xb3,0x2e,0xfa,0x2a,0x31,0x33,0x67,0x60,0x27,0x3d,0x87,0xcd,0x32,0x39,0xdb,0x5b };
    const uint8_t IV[] = { 0x8c,0x40,0xfd,0x88,0xa0,0x41,0x54,0xd7,0x46,0x9d,0xf0,0x9d,0xdd,0xc7,0xe2,0xce };
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

TEST_CASE("CFB1MCT256-DECRYPT-40", "[CFB1][MCT][256][DECRYPT][n40]") {
    const uint8_t KEY[] = { 0xe7,0xf7,0x44,0x4f,0x96,0x48,0x92,0xfc,0x71,0xa4,0xc4,0x71,0x04,0xc0,0x9d,0x7a,0x36,0x7b,0x70,0x28,0x8c,0x8d,0x2a,0xb9,0x23,0x7e,0xac,0xaa,0xe7,0x39,0x27,0xcb };
    const uint8_t IV[] = { 0x85,0x55,0x8a,0x02,0xbd,0xbe,0x4d,0xd9,0x04,0x43,0x2b,0x67,0xd5,0x00,0xfc,0x90 };
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

TEST_CASE("CFB1MCT256-DECRYPT-41", "[CFB1][MCT][256][DECRYPT][n41]") {
    const uint8_t KEY[] = { 0x19,0xc8,0x12,0x18,0xd0,0x8a,0x97,0xf3,0xaa,0x9d,0x38,0x09,0x90,0xdb,0x65,0x62,0xdb,0x15,0x00,0x2d,0x2e,0xad,0xd4,0xb5,0xb3,0xe1,0xa2,0x74,0x18,0x2c,0xe9,0x58 };
    const uint8_t IV[] = { 0xed,0x6e,0x70,0x05,0xa2,0x20,0xfe,0x0c,0x90,0x9f,0x0e,0xde,0xff,0x15,0xce,0x93 };
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

TEST_CASE("CFB1MCT256-DECRYPT-42", "[CFB1][MCT][256][DECRYPT][n42]") {
    const uint8_t KEY[] = { 0x69,0xea,0xf8,0x79,0x0d,0xfa,0x05,0x19,0xbd,0x9c,0x1c,0x08,0xcf,0xc9,0x70,0x9e,0x62,0xaa,0x68,0x47,0x34,0xd8,0x7f,0x76,0x60,0xd4,0x93,0x27,0xca,0xfd,0xb5,0x42 };
    const uint8_t IV[] = { 0xb9,0xbf,0x68,0x6a,0x1a,0x75,0xab,0xc3,0xd3,0x35,0x31,0x53,0xd2,0xd1,0x5c,0x1a };
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

TEST_CASE("CFB1MCT256-DECRYPT-43", "[CFB1][MCT][256][DECRYPT][n43]") {
    const uint8_t KEY[] = { 0x39,0xca,0xdd,0xf0,0x4c,0x4e,0x33,0xc5,0x44,0x05,0xef,0xd3,0x68,0x56,0xfb,0x82,0xb0,0x1f,0x69,0xe6,0xd4,0xc4,0x0c,0x7c,0xac,0x53,0x34,0xf6,0x3c,0xb8,0x3c,0xec };
    const uint8_t IV[] = { 0xd2,0xb5,0x01,0xa1,0xe0,0x1c,0x73,0x0a,0xcc,0x87,0xa7,0xd1,0xf6,0x45,0x89,0xae };
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

TEST_CASE("CFB1MCT256-DECRYPT-44", "[CFB1][MCT][256][DECRYPT][n44]") {
    const uint8_t KEY[] = { 0x61,0xfe,0x7a,0xc2,0x75,0xb7,0x25,0x8d,0x97,0xe8,0x82,0xa2,0x76,0x4c,0x60,0xe7,0xa7,0x5d,0x64,0x7a,0xc1,0xaf,0x42,0x08,0xa2,0x6e,0x5c,0xb2,0x62,0xa8,0x58,0x27 };
    const uint8_t IV[] = { 0x17,0x42,0x0d,0x9c,0x15,0x6b,0x4e,0x74,0x0e,0x3d,0x68,0x44,0x5e,0x10,0x64,0xcb };
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

TEST_CASE("CFB1MCT256-DECRYPT-45", "[CFB1][MCT][256][DECRYPT][n45]") {
    const uint8_t KEY[] = { 0x64,0xfe,0x5d,0x8d,0xfe,0x6b,0xd2,0x11,0x69,0x71,0x55,0xf8,0xb9,0x51,0x10,0x7b,0x74,0xe1,0x31,0xaa,0xdc,0x02,0xc3,0x86,0x8a,0xa3,0x93,0x3b,0x70,0xe3,0xe7,0x7c };
    const uint8_t IV[] = { 0xd3,0xbc,0x55,0xd0,0x1d,0xad,0x81,0x8e,0x28,0xcd,0xcf,0x89,0x12,0x4b,0xbf,0x5b };
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

TEST_CASE("CFB1MCT256-DECRYPT-46", "[CFB1][MCT][256][DECRYPT][n46]") {
    const uint8_t KEY[] = { 0x82,0x73,0xee,0x5b,0xff,0xa6,0x09,0x43,0x60,0x30,0x7d,0xa2,0x9b,0xec,0x23,0xf3,0x1f,0xc9,0x82,0x1c,0x2a,0xf0,0x96,0x29,0xcf,0x46,0xbd,0x31,0x1d,0x0a,0x55,0x89 };
    const uint8_t IV[] = { 0x6b,0x28,0xb3,0xb6,0xf6,0xf2,0x55,0xaf,0x45,0xe5,0x2e,0x0a,0x6d,0xe9,0xb2,0xf5 };
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

TEST_CASE("CFB1MCT256-DECRYPT-47", "[CFB1][MCT][256][DECRYPT][n47]") {
    const uint8_t KEY[] = { 0xeb,0xe7,0x4f,0x0f,0x6d,0x7c,0x65,0xf8,0x0e,0x33,0x7e,0x49,0x61,0xd9,0xad,0x29,0xcd,0xb9,0x7b,0x37,0x64,0xea,0xc9,0x79,0x22,0x04,0x13,0x75,0x7d,0x25,0xec,0xeb };
    const uint8_t IV[] = { 0xd2,0x70,0xf9,0x2b,0x4e,0x1a,0x5f,0x50,0xed,0x42,0xae,0x44,0x60,0x2f,0xb9,0x62 };
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

TEST_CASE("CFB1MCT256-DECRYPT-48", "[CFB1][MCT][256][DECRYPT][n48]") {
    const uint8_t KEY[] = { 0x82,0x73,0x4e,0x2b,0xc0,0x86,0xd4,0x6e,0xaf,0x24,0x07,0x9d,0xe8,0xd2,0xa1,0xac,0x94,0x95,0xd7,0xa5,0x9c,0x8f,0x18,0x09,0x3d,0x32,0xa5,0x5c,0x0b,0x0d,0x07,0x97 };
    const uint8_t IV[] = { 0x59,0x2c,0xac,0x92,0xf8,0x65,0xd1,0x70,0x1f,0x36,0xb6,0x29,0x76,0x28,0xeb,0x7c };
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

TEST_CASE("CFB1MCT256-DECRYPT-49", "[CFB1][MCT][256][DECRYPT][n49]") {
    const uint8_t KEY[] = { 0x39,0x61,0x40,0x06,0x92,0x00,0xa6,0xff,0xcb,0xa3,0x74,0x0e,0xf4,0xd9,0x62,0x9b,0xbd,0xb4,0xfc,0xb5,0x25,0xd0,0x99,0x91,0xc6,0x91,0xdf,0xae,0x05,0xae,0x47,0x1d };
    const uint8_t IV[] = { 0x29,0x21,0x2b,0x10,0xb9,0x5f,0x81,0x98,0xfb,0xa3,0x7a,0xf2,0x0e,0xa3,0x40,0x8a };
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

TEST_CASE("CFB1MCT256-DECRYPT-50", "[CFB1][MCT][256][DECRYPT][n50]") {
    const uint8_t KEY[] = { 0x4a,0x5b,0xd8,0xf0,0x78,0xc2,0x91,0x2c,0x9e,0x41,0x08,0x9c,0x09,0xd4,0x7e,0xe8,0x3a,0xe3,0xb6,0x72,0xc8,0xe8,0x6e,0xf8,0x3e,0x2b,0x20,0xec,0x18,0xc2,0xd9,0x0d };
    const uint8_t IV[] = { 0x87,0x57,0x4a,0xc7,0xed,0x38,0xf7,0x69,0xf8,0xba,0xff,0x42,0x1d,0x6c,0x9e,0x10 };
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

TEST_CASE("CFB1MCT256-DECRYPT-51", "[CFB1][MCT][256][DECRYPT][n51]") {
    const uint8_t KEY[] = { 0xcb,0xf6,0xdd,0x68,0x89,0x5d,0xb1,0x5c,0x70,0x3a,0x7a,0xb3,0xae,0xb6,0xf7,0x8c,0xf2,0xf8,0xcc,0xf1,0x85,0x86,0x61,0x11,0xa1,0xa3,0x3c,0x63,0xa2,0x92,0x56,0x6b };
    const uint8_t IV[] = { 0xc8,0x1b,0x7a,0x83,0x4d,0x6e,0x0f,0xe9,0x9f,0x88,0x1c,0x8f,0xba,0x50,0x8f,0x66 };
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

TEST_CASE("CFB1MCT256-DECRYPT-52", "[CFB1][MCT][256][DECRYPT][n52]") {
    const uint8_t KEY[] = { 0x5a,0xaf,0x1c,0x88,0x3a,0x1d,0x27,0xdd,0xe9,0x2a,0x46,0x7d,0x8b,0x25,0x55,0x9b,0xe5,0x23,0x2c,0xd7,0xe7,0x89,0x54,0x0f,0x43,0xbd,0xc8,0x48,0x2b,0xce,0x09,0x33 };
    const uint8_t IV[] = { 0x17,0xdb,0xe0,0x26,0x62,0x0f,0x35,0x1e,0xe2,0x1e,0xf4,0x2b,0x89,0x5c,0x5f,0x58 };
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

TEST_CASE("CFB1MCT256-DECRYPT-53", "[CFB1][MCT][256][DECRYPT][n53]") {
    const uint8_t KEY[] = { 0xa6,0xcc,0xe6,0xb4,0x54,0x4c,0xcc,0x90,0xc3,0xc9,0x9a,0xfa,0x42,0xcd,0x3a,0x76,0x77,0xe5,0x0d,0x0b,0x9a,0xef,0xd6,0x03,0x74,0x9c,0x79,0xe6,0x69,0x04,0x91,0x3c };
    const uint8_t IV[] = { 0x92,0xc6,0x21,0xdc,0x7d,0x66,0x82,0x0c,0x37,0x21,0xb1,0xae,0x42,0xca,0x98,0x0f };
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

TEST_CASE("CFB1MCT256-DECRYPT-54", "[CFB1][MCT][256][DECRYPT][n54]") {
    const uint8_t KEY[] = { 0x2e,0xe2,0x1f,0x64,0xc5,0xd2,0xff,0x5e,0xdf,0xfe,0xd6,0xed,0xc4,0xaa,0x80,0xa9,0x98,0x4c,0xbf,0xc3,0xd0,0xe8,0x73,0xe6,0xea,0xf2,0x66,0x4e,0x0b,0x2c,0x81,0xa1 };
    const uint8_t IV[] = { 0xef,0xa9,0xb2,0xc8,0x4a,0x07,0xa5,0xe5,0x9e,0x6e,0x1f,0xa8,0x62,0x28,0x10,0x9d };
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

TEST_CASE("CFB1MCT256-DECRYPT-55", "[CFB1][MCT][256][DECRYPT][n55]") {
    const uint8_t KEY[] = { 0xa6,0x37,0xfa,0x8e,0x24,0x80,0x3f,0x21,0x13,0x72,0xc0,0x06,0xd6,0x34,0xc4,0x4a,0xa3,0xb4,0x17,0x37,0xd1,0xd9,0x99,0x64,0xe7,0xc3,0xd1,0x74,0x53,0x38,0xd7,0x02 };
    const uint8_t IV[] = { 0x3b,0xf8,0xa8,0xf4,0x01,0x31,0xea,0x82,0x0d,0x31,0xb7,0x3a,0x58,0x14,0x56,0xa3 };
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

TEST_CASE("CFB1MCT256-DECRYPT-56", "[CFB1][MCT][256][DECRYPT][n56]") {
    const uint8_t KEY[] = { 0xb3,0x27,0x5e,0x27,0xc7,0x64,0xd5,0x2c,0x1c,0xd5,0xa8,0x71,0xea,0x39,0x2e,0x3c,0xcd,0x12,0xb6,0x75,0xff,0x7e,0x70,0xe3,0xed,0xd8,0xc8,0x29,0xc8,0x20,0xe0,0x71 };
    const uint8_t IV[] = { 0x6e,0xa6,0xa1,0x42,0x2e,0xa7,0xe9,0x87,0x0a,0x1b,0x19,0x5d,0x9b,0x18,0x37,0x73 };
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

TEST_CASE("CFB1MCT256-DECRYPT-57", "[CFB1][MCT][256][DECRYPT][n57]") {
    const uint8_t KEY[] = { 0x5d,0xa6,0xa3,0x1e,0x28,0x54,0xab,0x71,0x3b,0xe2,0xda,0x00,0x86,0x97,0x3d,0xf3,0xce,0xa9,0xa1,0x85,0x2d,0x07,0x33,0x31,0x95,0xf7,0xff,0xfa,0xf4,0x45,0xaf,0x06 };
    const uint8_t IV[] = { 0x03,0xbb,0x17,0xf0,0xd2,0x79,0x43,0xd2,0x78,0x2f,0x37,0xd3,0x3c,0x65,0x4f,0x77 };
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

TEST_CASE("CFB1MCT256-DECRYPT-58", "[CFB1][MCT][256][DECRYPT][n58]") {
    const uint8_t KEY[] = { 0x81,0x97,0xc2,0xcf,0x13,0xcd,0x80,0x83,0x18,0xc2,0xad,0x03,0xc6,0xbb,0x50,0x03,0x3e,0x31,0x85,0x74,0xfe,0x02,0x5a,0x8f,0xf9,0x1d,0x62,0xa6,0xbb,0x35,0x3d,0x0c };
    const uint8_t IV[] = { 0xf0,0x98,0x24,0xf1,0xd3,0x05,0x69,0xbe,0x6c,0xea,0x9d,0x5c,0x4f,0x70,0x92,0x0a };
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

TEST_CASE("CFB1MCT256-DECRYPT-59", "[CFB1][MCT][256][DECRYPT][n59]") {
    const uint8_t KEY[] = { 0x3d,0xe2,0x01,0x25,0x33,0x46,0xa8,0xa6,0x3a,0x8d,0x38,0x40,0x35,0x4d,0xa4,0xa2,0x56,0x2c,0x08,0x64,0x95,0x97,0x86,0x69,0xd6,0xe9,0x12,0x61,0x64,0xd1,0x1b,0x94 };
    const uint8_t IV[] = { 0x68,0x1d,0x8d,0x10,0x6b,0x95,0xdc,0xe6,0x2f,0xf4,0x70,0xc7,0xdf,0xe4,0x26,0x98 };
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

TEST_CASE("CFB1MCT256-DECRYPT-60", "[CFB1][MCT][256][DECRYPT][n60]") {
    const uint8_t KEY[] = { 0xe0,0x95,0x19,0x59,0x32,0x3f,0x2d,0x59,0x76,0x73,0x54,0x81,0x88,0x09,0x49,0x24,0xd9,0xb5,0xe8,0xeb,0xa1,0x45,0xc9,0xf5,0xa2,0x76,0xda,0x6f,0x0c,0x06,0x7c,0x5d };
    const uint8_t IV[] = { 0x8f,0x99,0xe0,0x8f,0x34,0xd2,0x4f,0x9c,0x74,0x9f,0xc8,0x0e,0x68,0xd7,0x67,0xc9 };
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

TEST_CASE("CFB1MCT256-DECRYPT-61", "[CFB1][MCT][256][DECRYPT][n61]") {
    const uint8_t KEY[] = { 0x00,0x61,0x42,0x3c,0x51,0xd3,0x31,0xa0,0x5e,0xaf,0x61,0x73,0x89,0xcd,0x99,0xfb,0x03,0xa5,0x00,0x73,0xcb,0xd6,0xda,0x3c,0xd1,0xb2,0x58,0x09,0xa5,0x21,0x4a,0x94 };
    const uint8_t IV[] = { 0xda,0x10,0xe8,0x98,0x6a,0x93,0x13,0xc9,0x73,0xc4,0x82,0x66,0xa9,0x27,0x36,0xc9 };
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

TEST_CASE("CFB1MCT256-DECRYPT-62", "[CFB1][MCT][256][DECRYPT][n62]") {
    const uint8_t KEY[] = { 0x2e,0x7a,0x32,0x62,0x69,0x98,0xd2,0xff,0x47,0x60,0xeb,0xf0,0x66,0xc8,0x21,0x17,0x94,0x59,0x04,0x51,0x49,0x02,0x71,0x55,0x7a,0xd0,0x7c,0x79,0xb4,0x42,0x56,0xf8 };
    const uint8_t IV[] = { 0x97,0xfc,0x04,0x22,0x82,0xd4,0xab,0x69,0xab,0x62,0x24,0x70,0x11,0x63,0x1c,0x6c };
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

TEST_CASE("CFB1MCT256-DECRYPT-63", "[CFB1][MCT][256][DECRYPT][n63]") {
    const uint8_t KEY[] = { 0x3c,0x24,0x1e,0xbf,0xb2,0x62,0xfe,0x99,0xb2,0xb5,0x4c,0x5a,0xe6,0xcc,0x4f,0xb6,0x7a,0xe8,0x48,0x68,0x66,0x9c,0xe6,0xe8,0x64,0x2e,0x0e,0x05,0x57,0x5d,0x6c,0x11 };
    const uint8_t IV[] = { 0xee,0xb1,0x4c,0x39,0x2f,0x9e,0x97,0xbd,0x1e,0xfe,0x72,0x7c,0xe3,0x1f,0x3a,0xe9 };
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

TEST_CASE("CFB1MCT256-DECRYPT-64", "[CFB1][MCT][256][DECRYPT][n64]") {
    const uint8_t KEY[] = { 0x09,0x46,0xe2,0xff,0x76,0xac,0x52,0xe4,0xaf,0xe3,0x74,0x7d,0x56,0x0c,0xb7,0x22,0x6d,0x3f,0xdc,0x2e,0xfb,0xb9,0x82,0xef,0xa5,0xbf,0xe7,0xa3,0x63,0x25,0x12,0x0b };
    const uint8_t IV[] = { 0x17,0xd7,0x94,0x46,0x9d,0x25,0x64,0x07,0xc1,0x91,0xe9,0xa6,0x34,0x78,0x7e,0x1a };
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

TEST_CASE("CFB1MCT256-DECRYPT-65", "[CFB1][MCT][256][DECRYPT][n65]") {
    const uint8_t KEY[] = { 0xc9,0xb7,0xc2,0xc9,0xd6,0x8f,0x40,0xd9,0x4c,0x17,0x24,0x89,0x98,0x97,0xda,0x38,0x2b,0x9d,0xad,0x0a,0xc6,0x0f,0xc2,0x10,0x30,0x02,0x94,0xae,0x6e,0x9b,0x87,0x61 };
    const uint8_t IV[] = { 0x46,0xa2,0x71,0x24,0x3d,0xb6,0x40,0xff,0x95,0xbd,0x73,0x0d,0x0d,0xbe,0x95,0x6a };
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

TEST_CASE("CFB1MCT256-DECRYPT-66", "[CFB1][MCT][256][DECRYPT][n66]") {
    const uint8_t KEY[] = { 0xc7,0xe1,0xa5,0xa5,0x71,0x96,0x77,0xd1,0x78,0xbc,0x70,0x28,0xc1,0x32,0x88,0xc6,0x57,0x2d,0x4d,0xa7,0x96,0x8a,0xea,0xbb,0x31,0x80,0x96,0x10,0x6c,0xc6,0x01,0x92 };
    const uint8_t IV[] = { 0x7c,0xb0,0xe0,0xad,0x50,0x85,0x28,0xab,0x01,0x82,0x02,0xbe,0x02,0x5d,0x86,0xf3 };
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

TEST_CASE("CFB1MCT256-DECRYPT-67", "[CFB1][MCT][256][DECRYPT][n67]") {
    const uint8_t KEY[] = { 0x42,0x0a,0x63,0xb5,0x09,0x9f,0x08,0xc2,0x4b,0x57,0xe5,0xb8,0xc0,0x5c,0xcd,0x2b,0xa1,0xa0,0xa7,0xc7,0x3f,0xf6,0x58,0x31,0x0a,0x67,0x1d,0x41,0x56,0x27,0xac,0xde };
    const uint8_t IV[] = { 0xf6,0x8d,0xea,0x60,0xa9,0x7c,0xb2,0x8a,0x3b,0xe7,0x8b,0x51,0x3a,0xe1,0xad,0x4c };
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

TEST_CASE("CFB1MCT256-DECRYPT-68", "[CFB1][MCT][256][DECRYPT][n68]") {
    const uint8_t KEY[] = { 0xcd,0xaf,0xde,0xef,0x90,0xb9,0x9e,0xc5,0xe1,0x68,0x6f,0xbd,0xa7,0xc7,0x86,0xc8,0xfb,0xc9,0x23,0x4d,0x0d,0x95,0x04,0x7d,0x5f,0xdf,0x6c,0xa3,0xc9,0xf1,0x7f,0xb6 };
    const uint8_t IV[] = { 0x5a,0x69,0x84,0x8a,0x32,0x63,0x5c,0x4c,0x55,0xb8,0x71,0xe2,0x9f,0xd6,0xd3,0x68 };
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

TEST_CASE("CFB1MCT256-DECRYPT-69", "[CFB1][MCT][256][DECRYPT][n69]") {
    const uint8_t KEY[] = { 0x5b,0x92,0x17,0x8b,0xdf,0xd1,0xfc,0x52,0xd6,0x53,0x5d,0xfb,0xaf,0x4e,0x55,0x84,0xf6,0x81,0x21,0x24,0xea,0x09,0x7d,0x1e,0xae,0x84,0xf6,0xa4,0x63,0x7f,0xcb,0x78 };
    const uint8_t IV[] = { 0x0d,0x48,0x02,0x69,0xe7,0x9c,0x79,0x63,0xf1,0x5b,0x9a,0x07,0xaa,0x8e,0xb4,0xce };
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

TEST_CASE("CFB1MCT256-DECRYPT-70", "[CFB1][MCT][256][DECRYPT][n70]") {
    const uint8_t KEY[] = { 0x51,0xd1,0x63,0x99,0x6b,0x69,0xdc,0x7f,0x75,0xb7,0xef,0x24,0x8c,0xb8,0x58,0xd6,0x6f,0x17,0x25,0xf2,0x4a,0x56,0x64,0x3c,0xb0,0x64,0x5e,0x5f,0xcf,0x5c,0xfc,0x0c };
    const uint8_t IV[] = { 0x99,0x96,0x04,0xd6,0xa0,0x5f,0x19,0x22,0x1e,0xe0,0xa8,0xfb,0xac,0x23,0x37,0x74 };
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

TEST_CASE("CFB1MCT256-DECRYPT-71", "[CFB1][MCT][256][DECRYPT][n71]") {
    const uint8_t KEY[] = { 0x53,0xc1,0x3d,0xf7,0xa4,0xad,0x9f,0x20,0x54,0x25,0xc9,0xd0,0x0d,0xeb,0x8b,0x19,0x8b,0x22,0x3f,0x0d,0x28,0x46,0x0a,0x81,0x1a,0xa0,0x9e,0x86,0xa7,0x0d,0x9d,0xaf };
    const uint8_t IV[] = { 0xe4,0x35,0x1a,0xff,0x62,0x10,0x6e,0xbd,0xaa,0xc4,0xc0,0xd9,0x68,0x51,0x61,0xa3 };
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

TEST_CASE("CFB1MCT256-DECRYPT-72", "[CFB1][MCT][256][DECRYPT][n72]") {
    const uint8_t KEY[] = { 0x9b,0x0e,0x5f,0x3f,0x17,0x6d,0xaf,0x9e,0xb4,0xfb,0xdd,0xaa,0xae,0xcd,0xcd,0x89,0x0e,0xab,0xf9,0x2d,0xf6,0xda,0xcf,0xf6,0x65,0x50,0xc5,0x44,0x45,0x3e,0x49,0xea };
    const uint8_t IV[] = { 0x85,0x89,0xc6,0x20,0xde,0x9c,0xc5,0x77,0x7f,0xf0,0x5b,0xc2,0xe2,0x33,0xd4,0x45 };
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

TEST_CASE("CFB1MCT256-DECRYPT-73", "[CFB1][MCT][256][DECRYPT][n73]") {
    const uint8_t KEY[] = { 0x6d,0x74,0x09,0x7b,0x72,0xbf,0x8e,0x29,0x97,0xf6,0x48,0x63,0xb1,0x5c,0x4f,0x25,0x3d,0x28,0xca,0x00,0x49,0x89,0x64,0xbb,0xc6,0x40,0x69,0x07,0x4a,0x7a,0x8a,0xc6 };
    const uint8_t IV[] = { 0x33,0x83,0x33,0x2d,0xbf,0x53,0xab,0x4d,0xa3,0x10,0xac,0x43,0x0f,0x44,0xc3,0x2c };
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

TEST_CASE("CFB1MCT256-DECRYPT-74", "[CFB1][MCT][256][DECRYPT][n74]") {
    const uint8_t KEY[] = { 0xad,0x4b,0xf3,0x7b,0xfe,0xbf,0x09,0x50,0x97,0xeb,0x99,0x13,0x3d,0xc6,0xd2,0xb5,0x70,0xb2,0x45,0x23,0x93,0x9d,0xa7,0x91,0xf1,0x7e,0x1d,0xed,0x16,0xf3,0x5a,0x4c };
    const uint8_t IV[] = { 0x4d,0x9a,0x8f,0x23,0xda,0x14,0xc3,0x2a,0x37,0x3e,0x74,0xea,0x5c,0x89,0xd0,0x8a };
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

TEST_CASE("CFB1MCT256-DECRYPT-75", "[CFB1][MCT][256][DECRYPT][n75]") {
    const uint8_t KEY[] = { 0x3c,0xed,0xcf,0xd4,0x52,0x26,0xad,0x7e,0xcf,0x30,0xe6,0x13,0x33,0xd8,0x9f,0x47,0xe0,0xda,0xc6,0x55,0x68,0xd4,0x0f,0xd0,0xa3,0xc6,0x02,0x95,0x0d,0xbf,0x10,0x7d };
    const uint8_t IV[] = { 0x90,0x68,0x83,0x76,0xfb,0x49,0xa8,0x41,0x52,0xb8,0x1f,0x78,0x1b,0x4c,0x4a,0x31 };
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

TEST_CASE("CFB1MCT256-DECRYPT-76", "[CFB1][MCT][256][DECRYPT][n76]") {
    const uint8_t KEY[] = { 0xd1,0x9a,0xc4,0x0e,0x0e,0x91,0xb2,0x7b,0x68,0x85,0x51,0xc7,0xdb,0xf0,0x8e,0x16,0xd1,0xf5,0x95,0xc2,0xd2,0x73,0x04,0xc2,0x89,0x68,0x0c,0xbc,0x3a,0x36,0x4b,0xf3 };
    const uint8_t IV[] = { 0x31,0x2f,0x53,0x97,0xba,0xa7,0x0b,0x12,0x2a,0xae,0x0e,0x29,0x37,0x89,0x5b,0x8e };
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

TEST_CASE("CFB1MCT256-DECRYPT-77", "[CFB1][MCT][256][DECRYPT][n77]") {
    const uint8_t KEY[] = { 0xfb,0xba,0x71,0xba,0x86,0x88,0x96,0x80,0xbf,0x63,0xc4,0xfd,0xeb,0xef,0x75,0x0e,0xdb,0xb3,0xe6,0x95,0xfc,0x8f,0x6c,0x34,0x6d,0x9e,0xa2,0x8f,0x55,0xcd,0x32,0xd1 };
    const uint8_t IV[] = { 0x0a,0x46,0x73,0x57,0x2e,0xfc,0x68,0xf6,0xe4,0xf6,0xae,0x33,0x6f,0xfb,0x79,0x22 };
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

TEST_CASE("CFB1MCT256-DECRYPT-78", "[CFB1][MCT][256][DECRYPT][n78]") {
    const uint8_t KEY[] = { 0x5f,0x00,0xee,0x48,0xd2,0xf9,0x54,0x85,0x74,0x96,0x4c,0xd0,0x99,0x49,0x75,0x6d,0x85,0x37,0xa5,0xd6,0xaf,0x6b,0x38,0x43,0x41,0x06,0x36,0x90,0x33,0xff,0x97,0x8d };
    const uint8_t IV[] = { 0x5e,0x84,0x43,0x43,0x53,0xe4,0x54,0x77,0x2c,0x98,0x94,0x1f,0x66,0x32,0xa5,0x5c };
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

TEST_CASE("CFB1MCT256-DECRYPT-79", "[CFB1][MCT][256][DECRYPT][n79]") {
    const uint8_t KEY[] = { 0x44,0x70,0xbc,0x4b,0x46,0xb9,0x48,0xd3,0xbe,0xbc,0x68,0x90,0xfc,0x58,0x98,0x8c,0x88,0x11,0xb3,0x7e,0x11,0x21,0x28,0xaa,0x4b,0xa5,0x14,0x75,0x81,0xaa,0x5c,0x42 };
    const uint8_t IV[] = { 0x0d,0x26,0x16,0xa8,0xbe,0x4a,0x10,0xe9,0x0a,0xa3,0x22,0xe5,0xb2,0x55,0xcb,0xcf };
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

TEST_CASE("CFB1MCT256-DECRYPT-80", "[CFB1][MCT][256][DECRYPT][n80]") {
    const uint8_t KEY[] = { 0x4c,0xef,0x21,0x0f,0x9f,0x1e,0xd0,0x37,0x85,0x59,0xfb,0x4c,0x4b,0x81,0xd2,0x7b,0xef,0x39,0xad,0x6d,0xd3,0xa8,0x2a,0x00,0x7b,0x58,0x2c,0xae,0xe9,0xab,0x04,0x29 };
    const uint8_t IV[] = { 0x67,0x28,0x1e,0x13,0xc2,0x89,0x02,0xaa,0x30,0xfd,0x38,0xdb,0x68,0x01,0x58,0x6b };
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

TEST_CASE("CFB1MCT256-DECRYPT-81", "[CFB1][MCT][256][DECRYPT][n81]") {
    const uint8_t KEY[] = { 0x76,0x9c,0x03,0x20,0xbf,0xb4,0xff,0xb7,0xcd,0xf4,0xba,0x1b,0x87,0x39,0x3d,0xf8,0x0e,0x12,0xc4,0xcf,0x5f,0x9e,0x98,0x2b,0xb0,0x3f,0xb6,0x22,0x1b,0x6a,0xf7,0x30 };
    const uint8_t IV[] = { 0xe1,0x2b,0x69,0xa2,0x8c,0x36,0xb2,0x2b,0xcb,0x67,0x9a,0x8c,0xf2,0xc1,0xf3,0x19 };
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

TEST_CASE("CFB1MCT256-DECRYPT-82", "[CFB1][MCT][256][DECRYPT][n82]") {
    const uint8_t KEY[] = { 0xc5,0xde,0x57,0x4a,0xee,0x19,0xa4,0x95,0xc1,0x6b,0x87,0x2f,0xe8,0xd6,0x78,0x31,0xe6,0xbd,0xa0,0x7a,0xe1,0x76,0x80,0xf3,0x38,0x39,0x77,0x42,0x68,0x89,0xdc,0x8e };
    const uint8_t IV[] = { 0xe8,0xaf,0x64,0xb5,0xbe,0xe8,0x18,0xd8,0x88,0x06,0xc1,0x60,0x73,0xe3,0x2b,0xbe };
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

TEST_CASE("CFB1MCT256-DECRYPT-83", "[CFB1][MCT][256][DECRYPT][n83]") {
    const uint8_t KEY[] = { 0x75,0xe0,0x91,0x59,0x59,0xc3,0x91,0xe9,0xb2,0x76,0x7b,0xfe,0xc7,0x94,0x73,0xce,0xfc,0xcf,0x16,0xd9,0xfb,0x48,0xe4,0x9a,0x9d,0xb3,0x78,0xd9,0x99,0xe4,0x0c,0x38 };
    const uint8_t IV[] = { 0x1a,0x72,0xb6,0xa3,0x1a,0x3e,0x64,0x69,0xa5,0x8a,0x0f,0x9b,0xf1,0x6d,0xd0,0xb6 };
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

TEST_CASE("CFB1MCT256-DECRYPT-84", "[CFB1][MCT][256][DECRYPT][n84]") {
    const uint8_t KEY[] = { 0xe5,0x60,0x15,0x99,0x01,0x95,0xfd,0x01,0x7a,0x09,0xc2,0x48,0x1e,0xd9,0xb5,0x7b,0x51,0xb3,0x28,0x2d,0xaa,0x6b,0xe9,0x19,0xb4,0x93,0x1e,0x13,0x86,0xc3,0xfc,0x27 };
    const uint8_t IV[] = { 0xad,0x7c,0x3e,0xf4,0x51,0x23,0x0d,0x83,0x29,0x20,0x66,0xca,0x1f,0x27,0xf0,0x1f };
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

TEST_CASE("CFB1MCT256-DECRYPT-85", "[CFB1][MCT][256][DECRYPT][n85]") {
    const uint8_t KEY[] = { 0x7b,0x30,0x69,0xe3,0x7e,0x0e,0x4c,0x13,0x50,0xe7,0x55,0xc1,0x76,0xa6,0x72,0x85,0x45,0x28,0x3e,0xab,0xaa,0x5b,0x1e,0xd3,0x6f,0x12,0x5b,0xa0,0x59,0x23,0x17,0x8c };
    const uint8_t IV[] = { 0x14,0x9b,0x16,0x86,0x00,0x30,0xf7,0xca,0xdb,0x81,0x45,0xb3,0xdf,0xe0,0xeb,0xab };
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

TEST_CASE("CFB1MCT256-DECRYPT-86", "[CFB1][MCT][256][DECRYPT][n86]") {
    const uint8_t KEY[] = { 0x51,0x75,0x28,0x0b,0xb6,0x94,0x73,0x3e,0x46,0x07,0x53,0x45,0xe0,0xeb,0xaa,0xf0,0xe6,0x06,0xec,0x5e,0x2c,0xbb,0x30,0xd1,0x38,0x1e,0x9e,0x3d,0x2e,0xfe,0x58,0xd3 };
    const uint8_t IV[] = { 0xa3,0x2e,0xd2,0xf5,0x86,0xe0,0x2e,0x02,0x57,0x0c,0xc5,0x9d,0x77,0xdd,0x4f,0x5f };
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

TEST_CASE("CFB1MCT256-DECRYPT-87", "[CFB1][MCT][256][DECRYPT][n87]") {
    const uint8_t KEY[] = { 0xfa,0x59,0xd9,0x62,0xd2,0xea,0x25,0x8a,0xbb,0x24,0xb1,0x54,0xe4,0x15,0xfe,0x5d,0x8c,0x76,0x15,0xa6,0xba,0xf2,0xe3,0xd8,0xeb,0x55,0x4c,0x96,0x91,0x7b,0x67,0x49 };
    const uint8_t IV[] = { 0x6a,0x70,0xf9,0xf8,0x96,0x49,0xd3,0x09,0xd3,0x4b,0xd2,0xab,0xbf,0x85,0x3f,0x9a };
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

TEST_CASE("CFB1MCT256-DECRYPT-88", "[CFB1][MCT][256][DECRYPT][n88]") {
    const uint8_t KEY[] = { 0x7d,0x7c,0x4b,0x24,0xe7,0x49,0x26,0x0b,0x72,0x48,0xc9,0xc4,0xac,0x43,0xef,0x9a,0x0f,0xc8,0x79,0xec,0x63,0xc7,0xb7,0xc9,0x14,0xfa,0x15,0xbd,0xe7,0x83,0xfc,0xbd };
    const uint8_t IV[] = { 0x83,0xbe,0x6c,0x4a,0xd9,0x35,0x54,0x11,0xff,0xaf,0x59,0x2b,0x76,0xf8,0x9b,0xf4 };
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

TEST_CASE("CFB1MCT256-DECRYPT-89", "[CFB1][MCT][256][DECRYPT][n89]") {
    const uint8_t KEY[] = { 0xbb,0x3d,0xd5,0xb7,0xbb,0xc2,0xd1,0x8a,0x01,0x38,0xa6,0xb6,0x9c,0xa8,0x2a,0x93,0xcd,0x3b,0xa1,0x7a,0x76,0x83,0xb9,0xc7,0x63,0x16,0xc6,0x15,0x85,0x2f,0x81,0x2a };
    const uint8_t IV[] = { 0xc2,0xf3,0xd8,0x96,0x15,0x44,0x0e,0x0e,0x77,0xec,0xd3,0xa8,0x62,0xac,0x7d,0x97 };
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

TEST_CASE("CFB1MCT256-DECRYPT-90", "[CFB1][MCT][256][DECRYPT][n90]") {
    const uint8_t KEY[] = { 0xd1,0x76,0xce,0xc3,0xf2,0x0e,0xed,0x11,0x35,0xe1,0x03,0x87,0x1f,0xb2,0x98,0xe8,0x46,0x42,0xdd,0x82,0xd4,0xc2,0xce,0x02,0xfe,0x44,0x9b,0x96,0x5f,0x00,0xbb,0x1f };
    const uint8_t IV[] = { 0x8b,0x79,0x7c,0xf8,0xa2,0x41,0x77,0xc5,0x9d,0x52,0x5d,0x83,0xda,0x2f,0x3a,0x35 };
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

TEST_CASE("CFB1MCT256-DECRYPT-91", "[CFB1][MCT][256][DECRYPT][n91]") {
    const uint8_t KEY[] = { 0xb0,0xde,0x4c,0x4d,0x78,0x93,0x65,0xd3,0x44,0x10,0x71,0x9d,0xdc,0x05,0xfd,0x66,0xa4,0x6a,0xa4,0x40,0x92,0x35,0x64,0x17,0xfc,0x30,0x67,0xab,0x78,0x42,0x5b,0x35 };
    const uint8_t IV[] = { 0xe2,0x28,0x79,0xc2,0x46,0xf7,0xaa,0x15,0x02,0x74,0xfc,0x3d,0x27,0x42,0xe0,0x2a };
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

TEST_CASE("CFB1MCT256-DECRYPT-92", "[CFB1][MCT][256][DECRYPT][n92]") {
    const uint8_t KEY[] = { 0xbf,0xea,0xb2,0x72,0xf2,0x52,0xe9,0xba,0x9e,0x43,0xeb,0x05,0xa8,0x80,0x72,0xf2,0x28,0x41,0x6f,0xda,0x7a,0x0b,0x9e,0x4b,0x28,0xea,0x86,0x6f,0xa7,0xc7,0x66,0x16 };
    const uint8_t IV[] = { 0x8c,0x2b,0xcb,0x9a,0xe8,0x3e,0xfa,0x5c,0xd4,0xda,0xe1,0xc4,0xdf,0x85,0x3d,0x23 };
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

TEST_CASE("CFB1MCT256-DECRYPT-93", "[CFB1][MCT][256][DECRYPT][n93]") {
    const uint8_t KEY[] = { 0x57,0xe4,0xf5,0xb3,0xf1,0x69,0x07,0x60,0x86,0x7d,0xc7,0xfb,0xb1,0xfc,0x55,0x36,0x30,0xef,0x6e,0x19,0x71,0xcb,0x92,0x9e,0xb4,0x6b,0x2c,0x47,0x5d,0x6f,0x14,0x22 };
    const uint8_t IV[] = { 0x18,0xae,0x01,0xc3,0x0b,0xc0,0x0c,0xd5,0x9c,0x81,0xaa,0x28,0xfa,0xa8,0x72,0x34 };
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

TEST_CASE("CFB1MCT256-DECRYPT-94", "[CFB1][MCT][256][DECRYPT][n94]") {
    const uint8_t KEY[] = { 0xde,0xc3,0x59,0x96,0x50,0xc4,0x81,0x3f,0x07,0x03,0xa4,0xba,0x04,0xd2,0x75,0x5f,0xcb,0xe7,0x94,0x76,0x2c,0x1d,0xbc,0x6d,0x86,0x69,0xe4,0xd5,0x0f,0x86,0x7c,0x9c };
    const uint8_t IV[] = { 0xfb,0x08,0xfa,0x6f,0x5d,0xd6,0x2e,0xf3,0x32,0x02,0xc8,0x92,0x52,0xe9,0x68,0xbe };
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

TEST_CASE("CFB1MCT256-DECRYPT-95", "[CFB1][MCT][256][DECRYPT][n95]") {
    const uint8_t KEY[] = { 0x44,0xe0,0x75,0xf9,0xec,0xe2,0x71,0x09,0x0d,0xff,0xe5,0x40,0xb0,0xb3,0x7b,0x0f,0xb9,0x35,0xf4,0x11,0xce,0x4e,0xb7,0xb5,0x82,0xee,0xdd,0x67,0x7e,0xbf,0x35,0xa8 };
    const uint8_t IV[] = { 0x72,0xd2,0x60,0x67,0xe2,0x53,0x0b,0xd8,0x04,0x87,0x39,0xb2,0x71,0x39,0x49,0x34 };
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

TEST_CASE("CFB1MCT256-DECRYPT-96", "[CFB1][MCT][256][DECRYPT][n96]") {
    const uint8_t KEY[] = { 0xbc,0x6c,0x40,0x11,0xe8,0xcd,0xfd,0xa0,0x58,0xaf,0xb9,0x73,0x3b,0xf5,0xf3,0x19,0x49,0xe6,0x3a,0xc1,0x7c,0xc5,0x7b,0x69,0xec,0xd2,0x1a,0x87,0x22,0x19,0xc2,0x70 };
    const uint8_t IV[] = { 0xf0,0xd3,0xce,0xd0,0xb2,0x8b,0xcc,0xdc,0x6e,0x3c,0xc7,0xe0,0x5c,0xa6,0xf7,0xd8 };
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

TEST_CASE("CFB1MCT256-DECRYPT-97", "[CFB1][MCT][256][DECRYPT][n97]") {
    const uint8_t KEY[] = { 0x50,0x58,0xf6,0xe9,0xac,0x13,0x6b,0xbd,0x13,0xeb,0xb2,0xcf,0xa8,0x01,0x5f,0xa4,0xf0,0xa5,0x4d,0xd6,0xbd,0x43,0x6a,0x10,0xce,0x96,0x0e,0x5b,0x7a,0xf7,0x9d,0x9f };
    const uint8_t IV[] = { 0xb9,0x43,0x77,0x17,0xc1,0x86,0x11,0x79,0x22,0x44,0x14,0xdc,0x58,0xee,0x5f,0xef };
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

TEST_CASE("CFB1MCT256-DECRYPT-98", "[CFB1][MCT][256][DECRYPT][n98]") {
    const uint8_t KEY[] = { 0x70,0xfc,0xf8,0x6b,0xed,0x69,0x12,0xe1,0xaa,0x8e,0x87,0x70,0x9e,0xa7,0x7a,0x3b,0x90,0xf4,0x25,0x80,0xa4,0xec,0x66,0x99,0x9d,0x19,0x6a,0xb4,0xa5,0x78,0x08,0x2c };
    const uint8_t IV[] = { 0x60,0x51,0x68,0x56,0x19,0xaf,0x0c,0x89,0x53,0x8f,0x64,0xef,0xdf,0x8f,0x95,0xb3 };
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

TEST_CASE("CFB1MCT256-DECRYPT-99", "[CFB1][MCT][256][DECRYPT][n99]") {
    const uint8_t KEY[] = { 0x9a,0xfe,0xcf,0xde,0x89,0x2d,0x9e,0xea,0x73,0x12,0xb0,0x3d,0xfe,0xfc,0x0a,0x50,0x44,0x79,0x2b,0x68,0xf4,0xf1,0x8a,0x39,0x62,0x15,0xe9,0x90,0x9a,0x01,0x58,0x20 };
    const uint8_t IV[] = { 0xd4,0x8d,0x0e,0xe8,0x50,0x1d,0xec,0xa0,0xff,0x0c,0x83,0x24,0x3f,0x79,0x50,0x0c };
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

