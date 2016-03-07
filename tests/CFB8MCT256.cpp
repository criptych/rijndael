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

TEST_CASE("CFB8MCT256-ENCRYPT-0", "[CFB8][MCT][256][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0x7c,0x04,0x65,0x46,0xc5,0x54,0x2f,0xf9,0xc0,0x68,0x23,0xcc,0x78,0xef,0xc2,0x8e,0x8f,0xd1,0xe8,0xff,0xd5,0x6f,0xfc,0x36,0x19,0x2c,0x6a,0x40,0x40,0x2c,0x53,0x0a };
    const uint8_t IV[] = { 0xea,0x42,0xa2,0xfb,0x73,0xb3,0x6b,0x89,0x51,0xc1,0x87,0xa1,0x02,0x05,0xfc,0xc4 };
    const uint8_t PLAINTEXT[] = { 0xb9 };
    const uint8_t CIPHERTEXT[] = { 0x5a };
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

TEST_CASE("CFB8MCT256-ENCRYPT-1", "[CFB8][MCT][256][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0x51,0xb5,0xee,0x29,0x09,0xa4,0xb9,0x8e,0xab,0x6e,0xf1,0xbf,0x8d,0x4a,0xe4,0xc3,0x6b,0x04,0x84,0xbf,0x1d,0xa5,0x24,0x0e,0xe3,0x7b,0x52,0xcc,0x40,0x53,0x36,0x50 };
    const uint8_t IV[] = { 0xe4,0xd5,0x6c,0x40,0xc8,0xca,0xd8,0x38,0xfa,0x57,0x38,0x8c,0x00,0x7f,0x65,0x5a };
    const uint8_t PLAINTEXT[] = { 0x4d };
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

TEST_CASE("CFB8MCT256-ENCRYPT-2", "[CFB8][MCT][256][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0xfd,0x23,0xcb,0x22,0x10,0x65,0x98,0xb7,0x30,0x22,0x03,0xd6,0xc5,0xee,0xbf,0x23,0x6e,0x4b,0xe9,0x71,0x9f,0x82,0x50,0x54,0x41,0x3d,0x96,0xb3,0xdf,0x08,0x98,0x30 };
    const uint8_t IV[] = { 0x05,0x4f,0x6d,0xce,0x82,0x27,0x74,0x5a,0xa2,0x46,0xc4,0x7f,0x9f,0x5b,0xae,0x60 };
    const uint8_t PLAINTEXT[] = { 0xe0 };
    const uint8_t CIPHERTEXT[] = { 0x8e };
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

TEST_CASE("CFB8MCT256-ENCRYPT-3", "[CFB8][MCT][256][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0xa5,0x2a,0x61,0xea,0xf0,0x55,0x03,0x6c,0x44,0xdd,0x76,0x52,0x69,0x0b,0xc2,0x83,0x64,0xf6,0xec,0x12,0xc3,0xe8,0xca,0xda,0xa5,0xea,0x8f,0x02,0xe9,0x46,0xd2,0xbe };
    const uint8_t IV[] = { 0x0a,0xbd,0x05,0x63,0x5c,0x6a,0x9a,0x8e,0xe4,0xd7,0x19,0xb1,0x36,0x4e,0x4a,0x8e };
    const uint8_t PLAINTEXT[] = { 0xa0 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-4", "[CFB8][MCT][256][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0x52,0x68,0x0c,0x3d,0x90,0x5d,0x07,0xd9,0x5c,0xd5,0xfc,0xa4,0x90,0x0c,0x79,0x83,0xc5,0xd0,0x3b,0x57,0x56,0x89,0x59,0x06,0xb8,0x00,0x9b,0xe8,0xa4,0xd2,0xb3,0xba };
    const uint8_t IV[] = { 0xa1,0x26,0xd7,0x45,0x95,0x61,0x93,0xdc,0x1d,0xea,0x14,0xea,0x4d,0x94,0x61,0x04 };
    const uint8_t PLAINTEXT[] = { 0x00 };
    const uint8_t CIPHERTEXT[] = { 0x19 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-5", "[CFB8][MCT][256][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0x06,0xd6,0x20,0xd4,0xec,0x8e,0x41,0xd5,0xf4,0x51,0xeb,0xb0,0xdf,0x68,0xa6,0x78,0xc1,0x82,0xac,0xd2,0x1a,0xa2,0x25,0x06,0x90,0x12,0xc7,0x3f,0xc6,0x54,0x81,0xa3 };
    const uint8_t IV[] = { 0x04,0x52,0x97,0x85,0x4c,0x2b,0x7c,0x00,0x28,0x12,0x5c,0xd7,0x62,0x86,0x32,0x19 };
    const uint8_t PLAINTEXT[] = { 0xfb };
    const uint8_t CIPHERTEXT[] = { 0xb2 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-6", "[CFB8][MCT][256][ENCRYPT][n6]") {
    const uint8_t KEY[] = { 0xda,0xb7,0x7e,0xbc,0x6e,0x04,0xb5,0x99,0x46,0xc5,0xea,0xa0,0xc2,0xe8,0xff,0x83,0x7e,0xbe,0xd0,0x57,0x5e,0x97,0x5c,0xf6,0x9a,0x3b,0x46,0x6a,0xf3,0x28,0x81,0x11 };
    const uint8_t IV[] = { 0xbf,0x3c,0x7c,0x85,0x44,0x35,0x79,0xf0,0x0a,0x29,0x81,0x55,0x35,0x7c,0x00,0xb2 };
    const uint8_t PLAINTEXT[] = { 0xfb };
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

TEST_CASE("CFB8MCT256-ENCRYPT-7", "[CFB8][MCT][256][ENCRYPT][n7]") {
    const uint8_t KEY[] = { 0x48,0x3a,0xb5,0x0d,0x85,0xa9,0x4e,0x71,0xd3,0x65,0x41,0x9f,0xd2,0x72,0xb4,0xef,0x22,0x24,0x0b,0xd9,0x3e,0x9b,0x25,0x07,0xc7,0xcd,0xb2,0x40,0x2d,0x1a,0xaf,0x1e };
    const uint8_t IV[] = { 0x5c,0x9a,0xdb,0x8e,0x60,0x0c,0x79,0xf1,0x5d,0xf6,0xf4,0x2a,0xde,0x32,0x2e,0x0f };
    const uint8_t PLAINTEXT[] = { 0x6c };
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

TEST_CASE("CFB8MCT256-ENCRYPT-8", "[CFB8][MCT][256][ENCRYPT][n8]") {
    const uint8_t KEY[] = { 0x39,0x07,0x9c,0xfd,0x9e,0x68,0x25,0x26,0x0a,0x7c,0xd6,0x8a,0xc7,0x08,0x22,0x7f,0x8e,0x5e,0xc8,0x57,0x45,0x74,0xff,0xfb,0xcb,0xea,0x8f,0xba,0x5d,0x0f,0x52,0xc2 };
    const uint8_t IV[] = { 0xac,0x7a,0xc3,0x8e,0x7b,0xef,0xda,0xfc,0x0c,0x27,0x3d,0xfa,0x70,0x15,0xfd,0xdc };
    const uint8_t PLAINTEXT[] = { 0x90 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-9", "[CFB8][MCT][256][ENCRYPT][n9]") {
    const uint8_t KEY[] = { 0x7d,0xc1,0xf5,0x99,0xeb,0x1e,0x8e,0xda,0x31,0x7e,0xf7,0x15,0x50,0x48,0x63,0xbc,0x23,0xdd,0xc6,0xe5,0xe9,0x6d,0x30,0xd0,0x8a,0xa2,0x42,0xbc,0xa5,0xc0,0x0c,0xe3 };
    const uint8_t IV[] = { 0xad,0x83,0x0e,0xb2,0xac,0x19,0xcf,0x2b,0x41,0x48,0xcd,0x06,0xf8,0xcf,0x5e,0x21 };
    const uint8_t PLAINTEXT[] = { 0xc3 };
    const uint8_t CIPHERTEXT[] = { 0x70 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-10", "[CFB8][MCT][256][ENCRYPT][n10]") {
    const uint8_t KEY[] = { 0x65,0xe7,0x88,0x52,0x58,0x54,0x51,0xd6,0xa9,0x67,0x48,0x9c,0x4c,0x22,0xcd,0xa1,0xfb,0x21,0x5f,0xcf,0xd7,0xaa,0xa3,0x48,0x82,0x04,0xa8,0x95,0x4a,0x8b,0xf8,0x93 };
    const uint8_t IV[] = { 0xd8,0xfc,0x99,0x2a,0x3e,0xc7,0x93,0x98,0x08,0xa6,0xea,0x29,0xef,0x4b,0xf4,0x70 };
    const uint8_t PLAINTEXT[] = { 0x1d };
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

TEST_CASE("CFB8MCT256-ENCRYPT-11", "[CFB8][MCT][256][ENCRYPT][n11]") {
    const uint8_t KEY[] = { 0x54,0xb1,0x76,0xc8,0x9a,0xcb,0x97,0x37,0xc8,0x24,0xe1,0xcf,0x1f,0x14,0xa7,0x0d,0xa8,0xa5,0xac,0x10,0xb6,0x51,0x2f,0x9c,0x72,0xb1,0x39,0x0e,0xa8,0x24,0x5a,0xaa };
    const uint8_t IV[] = { 0x53,0x84,0xf3,0xdf,0x61,0xfb,0x8c,0xd4,0xf0,0xb5,0x91,0x9b,0xe2,0xaf,0xa2,0x39 };
    const uint8_t PLAINTEXT[] = { 0xac };
    const uint8_t CIPHERTEXT[] = { 0x65 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-12", "[CFB8][MCT][256][ENCRYPT][n12]") {
    const uint8_t KEY[] = { 0xc4,0x4e,0xb9,0x72,0x9f,0x3a,0x52,0x3e,0x62,0xa2,0x63,0x63,0x7d,0x8b,0x32,0xe8,0xd6,0xa1,0x0d,0x97,0x9f,0xc2,0x3e,0x31,0xfd,0xec,0x06,0xce,0x93,0x63,0x34,0xcf };
    const uint8_t IV[] = { 0x7e,0x04,0xa1,0x87,0x29,0x93,0x11,0xad,0x8f,0x5d,0x3f,0xc0,0x3b,0x47,0x6e,0x65 };
    const uint8_t PLAINTEXT[] = { 0xe5 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-13", "[CFB8][MCT][256][ENCRYPT][n13]") {
    const uint8_t KEY[] = { 0x05,0x3f,0xf0,0xf6,0x34,0xef,0x41,0x43,0x73,0x11,0x63,0x83,0xd1,0xd0,0xe6,0xf3,0x0f,0x4a,0xcf,0x45,0x4c,0x32,0x12,0xf1,0xd8,0x26,0x9a,0x7b,0x62,0x7c,0xd4,0x4a };
    const uint8_t IV[] = { 0xd9,0xeb,0xc2,0xd2,0xd3,0xf0,0x2c,0xc0,0x25,0xca,0x9c,0xb5,0xf1,0x1f,0xe0,0x85 };
    const uint8_t PLAINTEXT[] = { 0x1b };
    const uint8_t CIPHERTEXT[] = { 0xba };
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

TEST_CASE("CFB8MCT256-ENCRYPT-14", "[CFB8][MCT][256][ENCRYPT][n14]") {
    const uint8_t KEY[] = { 0x04,0x87,0xe4,0x4e,0x6b,0xe0,0xd6,0xc4,0x3b,0x18,0xa0,0x17,0x82,0x36,0x3d,0x8d,0xe9,0x2d,0xae,0x41,0x1b,0x25,0xe0,0x1a,0xb2,0x5d,0xf0,0x46,0xc7,0xe6,0x03,0xf0 };
    const uint8_t IV[] = { 0xe6,0x67,0x61,0x04,0x57,0x17,0xf2,0xeb,0x6a,0x7b,0x6a,0x3d,0xa5,0x9a,0xd7,0xba };
    const uint8_t PLAINTEXT[] = { 0x7e };
    const uint8_t CIPHERTEXT[] = { 0xdb };
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

TEST_CASE("CFB8MCT256-ENCRYPT-15", "[CFB8][MCT][256][ENCRYPT][n15]") {
    const uint8_t KEY[] = { 0x45,0x33,0x56,0x3d,0x10,0x6c,0xfe,0xcd,0x1c,0x74,0x12,0xdc,0xf7,0xbb,0x75,0xaf,0xe6,0x91,0x55,0x28,0x0e,0x1e,0x90,0x2e,0x37,0x74,0x22,0x60,0xcf,0x8e,0xb3,0x2b };
    const uint8_t IV[] = { 0x0f,0xbc,0xfb,0x69,0x15,0x3b,0x70,0x34,0x85,0x29,0xd2,0x26,0x08,0x68,0xb0,0xdb };
    const uint8_t PLAINTEXT[] = { 0x22 };
    const uint8_t CIPHERTEXT[] = { 0x19 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-16", "[CFB8][MCT][256][ENCRYPT][n16]") {
    const uint8_t KEY[] = { 0x1f,0xf5,0xcf,0xbd,0xe8,0xdb,0x7a,0x37,0xc4,0x7b,0xae,0xc2,0x24,0x75,0x92,0x16,0x57,0x81,0xba,0x55,0x4a,0x2e,0x98,0x99,0x82,0x66,0x18,0x8a,0x4a,0x3a,0x10,0x32 };
    const uint8_t IV[] = { 0xb1,0x10,0xef,0x7d,0x44,0x30,0x08,0xb7,0xb5,0x12,0x3a,0xea,0x85,0xb4,0xa3,0x19 };
    const uint8_t PLAINTEXT[] = { 0xb9 };
    const uint8_t CIPHERTEXT[] = { 0xd7 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-17", "[CFB8][MCT][256][ENCRYPT][n17]") {
    const uint8_t KEY[] = { 0x65,0x0d,0x77,0x18,0x7a,0x95,0xbc,0xe1,0x63,0x56,0x35,0x8a,0xd3,0x34,0x02,0x2c,0x13,0x7a,0x53,0x56,0x5e,0x96,0x31,0xde,0x16,0xe1,0x77,0x43,0x27,0x73,0xff,0xe5 };
    const uint8_t IV[] = { 0x44,0xfb,0xe9,0x03,0x14,0xb8,0xa9,0x47,0x94,0x87,0x6f,0xc9,0x6d,0x49,0xef,0xd7 };
    const uint8_t PLAINTEXT[] = { 0x3a };
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

TEST_CASE("CFB8MCT256-ENCRYPT-18", "[CFB8][MCT][256][ENCRYPT][n18]") {
    const uint8_t KEY[] = { 0xe6,0x7a,0x12,0xd5,0xb7,0x61,0xc2,0x7b,0x7e,0xcf,0xe4,0xc7,0xe9,0xa0,0xa3,0x62,0x97,0x27,0x7e,0x01,0x83,0xa5,0x27,0xa6,0xd5,0x24,0x99,0xe1,0xe7,0xc3,0x07,0x25 };
    const uint8_t IV[] = { 0x84,0x5d,0x2d,0x57,0xdd,0x33,0x16,0x78,0xc3,0xc5,0xee,0xa2,0xc0,0xb0,0xf8,0xc0 };
    const uint8_t PLAINTEXT[] = { 0x4e };
    const uint8_t CIPHERTEXT[] = { 0xbf };
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

TEST_CASE("CFB8MCT256-ENCRYPT-19", "[CFB8][MCT][256][ENCRYPT][n19]") {
    const uint8_t KEY[] = { 0xad,0xfc,0xc2,0x30,0xfe,0x1f,0xc9,0x27,0xd7,0x1d,0x50,0x4d,0x2a,0x70,0x75,0xed,0xd5,0x1f,0x15,0x84,0xae,0x31,0x08,0xeb,0x8e,0xc2,0xc8,0xf2,0x18,0x7c,0xf6,0x9a };
    const uint8_t IV[] = { 0x42,0x38,0x6b,0x85,0x2d,0x94,0x2f,0x4d,0x5b,0xe6,0x51,0x13,0xff,0xbf,0xf1,0xbf };
    const uint8_t PLAINTEXT[] = { 0x8f };
    const uint8_t CIPHERTEXT[] = { 0x74 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-20", "[CFB8][MCT][256][ENCRYPT][n20]") {
    const uint8_t KEY[] = { 0x30,0x2f,0x54,0x8d,0x60,0xab,0xa7,0xe6,0x1f,0x8a,0x40,0x93,0x75,0xb1,0xb5,0xd8,0x10,0x69,0x17,0x1d,0x97,0x81,0x79,0xa4,0x45,0x97,0x1f,0x11,0x78,0x2b,0x09,0xee };
    const uint8_t IV[] = { 0xc5,0x76,0x02,0x99,0x39,0xb0,0x71,0x4f,0xcb,0x55,0xd7,0xe3,0x60,0x57,0xff,0x74 };
    const uint8_t PLAINTEXT[] = { 0x35 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-21", "[CFB8][MCT][256][ENCRYPT][n21]") {
    const uint8_t KEY[] = { 0xd3,0xc1,0x1e,0xb0,0xdb,0xd6,0x2a,0x5e,0x58,0xc1,0x63,0x97,0xf7,0x7f,0xee,0xf6,0xb9,0x40,0x3b,0x74,0x91,0x17,0xfc,0xbd,0x88,0xf7,0xe2,0x1f,0x1c,0x42,0xc0,0xd7 };
    const uint8_t IV[] = { 0xa9,0x29,0x2c,0x69,0x06,0x96,0x85,0x19,0xcd,0x60,0xfd,0x0e,0x64,0x69,0xc9,0x39 };
    const uint8_t PLAINTEXT[] = { 0x2e };
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

TEST_CASE("CFB8MCT256-ENCRYPT-22", "[CFB8][MCT][256][ENCRYPT][n22]") {
    const uint8_t KEY[] = { 0xdd,0xd1,0x0f,0xd6,0x7d,0x41,0xf2,0x26,0xbf,0x93,0x15,0x54,0xd8,0xe9,0xc5,0x0e,0x50,0x98,0xe8,0xcc,0x82,0xd0,0x57,0xa7,0x52,0x26,0x44,0xb2,0x8e,0x28,0x50,0xb4 };
    const uint8_t IV[] = { 0xe9,0xd8,0xd3,0xb8,0x13,0xc7,0xab,0x1a,0xda,0xd1,0xa6,0xad,0x92,0x6a,0x90,0x63 };
    const uint8_t PLAINTEXT[] = { 0xf8 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-23", "[CFB8][MCT][256][ENCRYPT][n23]") {
    const uint8_t KEY[] = { 0x58,0xf0,0xcf,0x9a,0x03,0x8c,0x54,0x4d,0xe7,0xbd,0xad,0x69,0xec,0xab,0x7a,0x52,0x46,0x87,0x56,0x67,0x71,0x30,0xcb,0x88,0x7f,0x25,0x9f,0x8b,0x61,0x13,0x4d,0x4e };
    const uint8_t IV[] = { 0x16,0x1f,0xbe,0xab,0xf3,0xe0,0x9c,0x2f,0x2d,0x03,0xdb,0x39,0xef,0x3b,0x1d,0xfa };
    const uint8_t PLAINTEXT[] = { 0x5c };
    const uint8_t CIPHERTEXT[] = { 0x70 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-24", "[CFB8][MCT][256][ENCRYPT][n24]") {
    const uint8_t KEY[] = { 0x2f,0xa4,0x07,0x64,0x77,0xed,0x43,0xdc,0x31,0xeb,0x20,0x89,0xdf,0x0c,0x61,0xe1,0x38,0x6a,0x70,0x0c,0x1a,0x59,0x37,0xc6,0x2f,0xcb,0xfc,0x81,0xa5,0xe1,0x24,0x3e };
    const uint8_t IV[] = { 0x7e,0xed,0x26,0x6b,0x6b,0x69,0xfc,0x4e,0x50,0xee,0x63,0x0a,0xc4,0xf2,0x69,0x70 };
    const uint8_t PLAINTEXT[] = { 0xb3 };
    const uint8_t CIPHERTEXT[] = { 0xb7 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-25", "[CFB8][MCT][256][ENCRYPT][n25]") {
    const uint8_t KEY[] = { 0x9d,0x96,0x87,0x1a,0xc9,0xa0,0x14,0xdb,0x90,0xf1,0x26,0xf9,0xce,0x03,0x61,0x76,0x9f,0x51,0x5b,0x8f,0xd6,0x22,0x9c,0x2e,0x77,0xb8,0xb5,0xc3,0x9b,0xac,0xd8,0x89 };
    const uint8_t IV[] = { 0xa7,0x3b,0x2b,0x83,0xcc,0x7b,0xab,0xe8,0x58,0x73,0x49,0x42,0x3e,0x4d,0xfc,0xb7 };
    const uint8_t PLAINTEXT[] = { 0x97 };
    const uint8_t CIPHERTEXT[] = { 0x4c };
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

TEST_CASE("CFB8MCT256-ENCRYPT-26", "[CFB8][MCT][256][ENCRYPT][n26]") {
    const uint8_t KEY[] = { 0xc4,0x72,0x0c,0x65,0xbb,0x95,0x1a,0xfd,0x51,0x37,0xe1,0x6b,0xc7,0x5b,0x6a,0x9e,0xf3,0x00,0x01,0x3b,0xbf,0x51,0xde,0x03,0x6b,0x34,0xbf,0xb0,0x16,0xa3,0xca,0xc5 };
    const uint8_t IV[] = { 0x6c,0x51,0x5a,0xb4,0x69,0x73,0x42,0x2d,0x1c,0x8c,0x0a,0x73,0x8d,0x0f,0x12,0x4c };
    const uint8_t PLAINTEXT[] = { 0xe8 };
    const uint8_t CIPHERTEXT[] = { 0x4f };
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

TEST_CASE("CFB8MCT256-ENCRYPT-27", "[CFB8][MCT][256][ENCRYPT][n27]") {
    const uint8_t KEY[] = { 0x6f,0x20,0x2f,0x8b,0x1e,0xb1,0x40,0xcc,0x6f,0x64,0x7c,0x18,0xb1,0xa6,0x7a,0x60,0x0e,0xff,0xe0,0x9c,0x75,0xd0,0x56,0x9e,0xf0,0x08,0x0c,0x1c,0xc5,0xa8,0x6d,0x8a };
    const uint8_t IV[] = { 0xfd,0xff,0xe1,0xa7,0xca,0x81,0x88,0x9d,0x9b,0x3c,0xb3,0xac,0xd3,0x0b,0xa7,0x4f };
    const uint8_t PLAINTEXT[] = { 0xfe };
    const uint8_t CIPHERTEXT[] = { 0x1d };
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

TEST_CASE("CFB8MCT256-ENCRYPT-28", "[CFB8][MCT][256][ENCRYPT][n28]") {
    const uint8_t KEY[] = { 0xfc,0xde,0xf6,0x42,0x11,0x42,0x94,0xf5,0xa9,0x2d,0xa7,0x01,0x17,0xa5,0xec,0xc8,0xc5,0x58,0x32,0x9f,0xf9,0x88,0x6b,0xd8,0xf9,0x8c,0x35,0x96,0x59,0xd9,0xc1,0x97 };
    const uint8_t IV[] = { 0xcb,0xa7,0xd2,0x03,0x8c,0x58,0x3d,0x46,0x09,0x84,0x39,0x8a,0x9c,0x71,0xac,0x1d };
    const uint8_t PLAINTEXT[] = { 0xa8 };
    const uint8_t CIPHERTEXT[] = { 0x9d };
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

TEST_CASE("CFB8MCT256-ENCRYPT-29", "[CFB8][MCT][256][ENCRYPT][n29]") {
    const uint8_t KEY[] = { 0xaa,0x87,0x5e,0xdc,0x1f,0xbb,0xc3,0x61,0x74,0xbf,0x5b,0xb8,0xa8,0xef,0xcb,0xe3,0x63,0xee,0x45,0x97,0xe1,0x23,0xd2,0x17,0xad,0x9f,0x6c,0xf3,0xef,0x16,0x67,0x0a };
    const uint8_t IV[] = { 0xa6,0xb6,0x77,0x08,0x18,0xab,0xb9,0xcf,0x54,0x13,0x59,0x65,0xb6,0xcf,0xa6,0x9d };
    const uint8_t PLAINTEXT[] = { 0x2b };
    const uint8_t CIPHERTEXT[] = { 0x12 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-30", "[CFB8][MCT][256][ENCRYPT][n30]") {
    const uint8_t KEY[] = { 0xf1,0xd6,0x8c,0x5c,0xa9,0x87,0xa7,0xe0,0xa1,0x78,0x1c,0x73,0x2e,0x3b,0x24,0xed,0x18,0xbf,0xde,0xd6,0xc5,0xd9,0x4b,0xf0,0x1d,0xe0,0x24,0xc7,0xb9,0x0f,0xe4,0x18 };
    const uint8_t IV[] = { 0x7b,0x51,0x9b,0x41,0x24,0xfa,0x99,0xe7,0xb0,0x7f,0x48,0x34,0x56,0x19,0x83,0x12 };
    const uint8_t PLAINTEXT[] = { 0x0e };
    const uint8_t CIPHERTEXT[] = { 0xf4 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-31", "[CFB8][MCT][256][ENCRYPT][n31]") {
    const uint8_t KEY[] = { 0x7f,0x7f,0xd3,0x35,0x93,0xd5,0x16,0xfc,0x48,0x66,0xc0,0x39,0xf1,0xce,0xc7,0x45,0x7f,0x85,0xcc,0xe6,0x7b,0x5b,0xcc,0xd5,0x72,0x84,0x66,0x87,0xae,0x51,0xa3,0xec };
    const uint8_t IV[] = { 0x67,0x3a,0x12,0x30,0xbe,0x82,0x87,0x25,0x6f,0x64,0x42,0x40,0x17,0x5e,0x47,0xf4 };
    const uint8_t PLAINTEXT[] = { 0xa8 };
    const uint8_t CIPHERTEXT[] = { 0xa3 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-32", "[CFB8][MCT][256][ENCRYPT][n32]") {
    const uint8_t KEY[] = { 0x47,0xb8,0xde,0xdb,0x59,0x4a,0xe6,0x82,0x7b,0xd4,0xda,0xfe,0xea,0x1d,0x94,0xf5,0xc8,0x19,0xa3,0xfe,0xbf,0x19,0x6f,0x89,0x7c,0x1e,0xdc,0xbe,0x3c,0x84,0xf8,0x4f };
    const uint8_t IV[] = { 0xb7,0x9c,0x6f,0x18,0xc4,0x42,0xa3,0x5c,0x0e,0x9a,0xba,0x39,0x92,0xd5,0x5b,0xa3 };
    const uint8_t PLAINTEXT[] = { 0xb0 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-33", "[CFB8][MCT][256][ENCRYPT][n33]") {
    const uint8_t KEY[] = { 0x22,0x0c,0x94,0x57,0xa5,0xaf,0x3d,0xd5,0x4c,0x23,0xb0,0x5b,0x00,0xc9,0x23,0x90,0xe4,0x6d,0x17,0x6f,0xfe,0x47,0x7b,0xbc,0xe7,0x80,0xa2,0xac,0xd9,0xa5,0x44,0x11 };
    const uint8_t IV[] = { 0x2c,0x74,0xb4,0x91,0x41,0x5e,0x14,0x35,0x9b,0x9e,0x7e,0x12,0xe5,0x21,0xbc,0x5e };
    const uint8_t PLAINTEXT[] = { 0x65 };
    const uint8_t CIPHERTEXT[] = { 0xd1 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-34", "[CFB8][MCT][256][ENCRYPT][n34]") {
    const uint8_t KEY[] = { 0x6a,0xfc,0xbb,0x4c,0xcb,0xa4,0x08,0xe2,0x75,0x92,0x53,0x1f,0xdb,0x88,0xd4,0xcb,0x1c,0xf8,0x63,0x3e,0xaa,0xa3,0xbd,0x6a,0x9f,0x83,0x20,0x7c,0x61,0x5c,0x08,0xc0 };
    const uint8_t IV[] = { 0xf8,0x95,0x74,0x51,0x54,0xe4,0xc6,0xd6,0x78,0x03,0x82,0xd0,0xb8,0xf9,0x4c,0xd1 };
    const uint8_t PLAINTEXT[] = { 0x5b };
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

TEST_CASE("CFB8MCT256-ENCRYPT-35", "[CFB8][MCT][256][ENCRYPT][n35]") {
    const uint8_t KEY[] = { 0x0c,0x4d,0x8b,0xbc,0x7a,0x76,0xbd,0xd8,0xa6,0x4e,0xe6,0xc2,0xcb,0x4c,0x94,0x2b,0x3c,0x8b,0xd5,0x9e,0x95,0xcf,0x06,0xcc,0xbd,0xd5,0x74,0xa1,0x53,0xe8,0x3b,0xa6 };
    const uint8_t IV[] = { 0x20,0x73,0xb6,0xa0,0x3f,0x6c,0xbb,0xa6,0x22,0x56,0x54,0xdd,0x32,0xb4,0x33,0x66 };
    const uint8_t PLAINTEXT[] = { 0xe0 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-36", "[CFB8][MCT][256][ENCRYPT][n36]") {
    const uint8_t KEY[] = { 0xe0,0xd8,0xdb,0x1e,0xfa,0xc1,0x8a,0x89,0xf0,0x17,0xdc,0x11,0xd3,0x13,0x93,0xc9,0xc3,0x5e,0x67,0x58,0x44,0x96,0x7e,0xe4,0x86,0x74,0x5e,0xb2,0x9a,0xe0,0x1f,0x79 };
    const uint8_t IV[] = { 0xff,0xd5,0xb2,0xc6,0xd1,0x59,0x78,0x28,0x3b,0xa1,0x2a,0x13,0xc9,0x08,0x24,0xdf };
    const uint8_t PLAINTEXT[] = { 0xe2 };
    const uint8_t CIPHERTEXT[] = { 0xa2 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-37", "[CFB8][MCT][256][ENCRYPT][n37]") {
    const uint8_t KEY[] = { 0xc4,0xf1,0xb2,0x5d,0x5d,0xad,0xa5,0xa8,0x84,0xd5,0x01,0x7c,0x2c,0x0f,0x76,0xed,0x34,0x19,0x70,0xf8,0xbe,0xed,0xdf,0x4c,0xa9,0x12,0xcd,0x97,0x2d,0x53,0xb2,0xdb };
    const uint8_t IV[] = { 0xf7,0x47,0x17,0xa0,0xfa,0x7b,0xa1,0xa8,0x2f,0x66,0x93,0x25,0xb7,0xb3,0xad,0xa2 };
    const uint8_t PLAINTEXT[] = { 0x24 };
    const uint8_t CIPHERTEXT[] = { 0x30 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-38", "[CFB8][MCT][256][ENCRYPT][n38]") {
    const uint8_t KEY[] = { 0x2f,0x8f,0xa0,0xc0,0x6f,0x17,0x74,0xa0,0x56,0x87,0x21,0x46,0x8d,0xe9,0xc4,0x49,0xae,0xac,0x7f,0xbc,0xb4,0x6e,0x70,0x59,0xad,0xc0,0xbe,0xb6,0x32,0x3e,0x2e,0xeb };
    const uint8_t IV[] = { 0x9a,0xb5,0x0f,0x44,0x0a,0x83,0xaf,0x15,0x04,0xd2,0x73,0x21,0x1f,0x6d,0x9c,0x30 };
    const uint8_t PLAINTEXT[] = { 0xa4 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-39", "[CFB8][MCT][256][ENCRYPT][n39]") {
    const uint8_t KEY[] = { 0x0c,0x9e,0x43,0xc3,0x94,0xa0,0x1e,0xf2,0x0f,0x9d,0xdb,0x65,0xb1,0x83,0xfc,0x9f,0x69,0xad,0xfa,0x03,0x06,0x90,0x77,0x66,0x76,0xda,0xaa,0xd0,0x2d,0x8b,0x9f,0xd5 };
    const uint8_t IV[] = { 0xc7,0x01,0x85,0xbf,0xb2,0xfe,0x07,0x3f,0xdb,0x1a,0x14,0x66,0x1f,0xb5,0xb1,0x3e };
    const uint8_t PLAINTEXT[] = { 0xd6 };
    const uint8_t CIPHERTEXT[] = { 0xbb };
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

TEST_CASE("CFB8MCT256-ENCRYPT-40", "[CFB8][MCT][256][ENCRYPT][n40]") {
    const uint8_t KEY[] = { 0x7a,0x20,0x9f,0x20,0x0b,0xc6,0x9b,0x84,0xa2,0x72,0x58,0x8c,0x51,0x0b,0xc9,0xa3,0xd4,0x43,0x95,0x0f,0x3a,0xae,0x91,0x79,0x39,0xfd,0x65,0xb9,0x4e,0xdb,0x34,0x6e };
    const uint8_t IV[] = { 0xbd,0xee,0x6f,0x0c,0x3c,0x3e,0xe6,0x1f,0x4f,0x27,0xcf,0x69,0x63,0x50,0xab,0xbb };
    const uint8_t PLAINTEXT[] = { 0x3c };
    const uint8_t CIPHERTEXT[] = { 0x17 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-41", "[CFB8][MCT][256][ENCRYPT][n41]") {
    const uint8_t KEY[] = { 0x00,0x1e,0x2d,0xf6,0x71,0x80,0xb2,0x81,0x9f,0x4b,0x2d,0x98,0x9e,0x70,0x22,0xa6,0x3b,0xfa,0x59,0x11,0x3f,0x61,0xab,0xad,0xec,0xa3,0xf5,0x86,0xf0,0x39,0xf5,0x79 };
    const uint8_t IV[] = { 0xef,0xb9,0xcc,0x1e,0x05,0xcf,0x3a,0xd4,0xd5,0x5e,0x90,0x3f,0xbe,0xe2,0xc1,0x17 };
    const uint8_t PLAINTEXT[] = { 0x05 };
    const uint8_t CIPHERTEXT[] = { 0xcb };
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

TEST_CASE("CFB8MCT256-ENCRYPT-42", "[CFB8][MCT][256][ENCRYPT][n42]") {
    const uint8_t KEY[] = { 0x39,0x29,0xd1,0xfd,0x26,0x47,0x6d,0x08,0x7e,0xc2,0x5f,0x1d,0x1e,0x1f,0x83,0xd0,0xee,0xe2,0xe9,0x48,0x4b,0x72,0x09,0x0e,0x23,0x5c,0x36,0x94,0xcf,0x8a,0x5e,0xb2 };
    const uint8_t IV[] = { 0xd5,0x18,0xb0,0x59,0x74,0x13,0xa2,0xa3,0xcf,0xff,0xc3,0x12,0x3f,0xb3,0xab,0xcb };
    const uint8_t PLAINTEXT[] = { 0x76 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-43", "[CFB8][MCT][256][ENCRYPT][n43]") {
    const uint8_t KEY[] = { 0xfb,0xc1,0xdb,0x61,0xfa,0x45,0x02,0xf5,0x6a,0x45,0xed,0x07,0xa7,0xa2,0x26,0x30,0x56,0x98,0x38,0xab,0x9a,0xbf,0xad,0x52,0xe6,0x03,0xd2,0x90,0x36,0x14,0xff,0x41 };
    const uint8_t IV[] = { 0xb8,0x7a,0xd1,0xe3,0xd1,0xcd,0xa4,0x5c,0xc5,0x5f,0xe4,0x04,0xf9,0x9e,0xa1,0xf3 };
    const uint8_t PLAINTEXT[] = { 0xe0 };
    const uint8_t CIPHERTEXT[] = { 0xa4 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-44", "[CFB8][MCT][256][ENCRYPT][n44]") {
    const uint8_t KEY[] = { 0x92,0x86,0xe0,0xd9,0x16,0xec,0xee,0xd6,0x23,0xc2,0xd7,0x81,0xc1,0xd0,0xee,0x34,0x30,0x51,0xf5,0xb8,0x48,0x8c,0x44,0x00,0x0d,0x98,0xf6,0x72,0x15,0x38,0x62,0xe5 };
    const uint8_t IV[] = { 0x66,0xc9,0xcd,0x13,0xd2,0x33,0xe9,0x52,0xeb,0x9b,0x24,0xe2,0x23,0x2c,0x9d,0xa4 };
    const uint8_t PLAINTEXT[] = { 0x04 };
    const uint8_t CIPHERTEXT[] = { 0xda };
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

TEST_CASE("CFB8MCT256-ENCRYPT-45", "[CFB8][MCT][256][ENCRYPT][n45]") {
    const uint8_t KEY[] = { 0xad,0x3c,0xe7,0x87,0x44,0x61,0xee,0x0e,0xfb,0xf2,0xca,0x90,0x7d,0xac,0xd8,0x87,0x2d,0x05,0x59,0xa8,0x44,0x9a,0x4f,0xd1,0x5f,0x1d,0xb8,0xb2,0x50,0x9d,0xf3,0x3f };
    const uint8_t IV[] = { 0x1d,0x54,0xac,0x10,0x0c,0x16,0x0b,0xd1,0x52,0x85,0x4e,0xc0,0x45,0xa5,0x91,0xda };
    const uint8_t PLAINTEXT[] = { 0xb3 };
    const uint8_t CIPHERTEXT[] = { 0xad };
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

TEST_CASE("CFB8MCT256-ENCRYPT-46", "[CFB8][MCT][256][ENCRYPT][n46]") {
    const uint8_t KEY[] = { 0xdb,0xc8,0xd2,0x3b,0x68,0x0e,0x99,0xae,0x6c,0x71,0x80,0x89,0x80,0x65,0x48,0x68,0xba,0x43,0xb4,0x7f,0x5e,0x07,0x5b,0x68,0x2b,0x1b,0xf5,0xed,0x6c,0xef,0xce,0x92 };
    const uint8_t IV[] = { 0x97,0x46,0xed,0xd7,0x1a,0x9d,0x14,0xb9,0x74,0x06,0x4d,0x5f,0x3c,0x72,0x3d,0xad };
    const uint8_t PLAINTEXT[] = { 0xef };
    const uint8_t CIPHERTEXT[] = { 0xff };
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

TEST_CASE("CFB8MCT256-ENCRYPT-47", "[CFB8][MCT][256][ENCRYPT][n47]") {
    const uint8_t KEY[] = { 0xdf,0x93,0xbd,0x25,0x2d,0xad,0x8e,0xea,0xc1,0xa2,0xfb,0xb0,0xa9,0x39,0xce,0x46,0x24,0x07,0xaa,0xe7,0x8f,0x6f,0x63,0xaf,0xae,0x9b,0xdc,0x9a,0x98,0x41,0x27,0x6d };
    const uint8_t IV[] = { 0x9e,0x44,0x1e,0x98,0xd1,0x68,0x38,0xc7,0x85,0x80,0x29,0x77,0xf4,0xae,0xe9,0xff };
    const uint8_t PLAINTEXT[] = { 0x2e };
    const uint8_t CIPHERTEXT[] = { 0x0c };
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

TEST_CASE("CFB8MCT256-ENCRYPT-48", "[CFB8][MCT][256][ENCRYPT][n48]") {
    const uint8_t KEY[] = { 0xcc,0x96,0xdc,0xee,0x18,0xf7,0x96,0x33,0x6f,0xdd,0x1d,0xf4,0x54,0x0a,0x0e,0x5b,0xea,0x21,0x43,0xcd,0xc3,0x7c,0xd9,0x6b,0xd1,0x89,0x4b,0xc0,0xf8,0x66,0x99,0x61 };
    const uint8_t IV[] = { 0xce,0x26,0xe9,0x2a,0x4c,0x13,0xba,0xc4,0x7f,0x12,0x97,0x5a,0x60,0x27,0xbe,0x0c };
    const uint8_t PLAINTEXT[] = { 0x1d };
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

TEST_CASE("CFB8MCT256-ENCRYPT-49", "[CFB8][MCT][256][ENCRYPT][n49]") {
    const uint8_t KEY[] = { 0x34,0x88,0x06,0x6d,0x9f,0x5e,0xce,0xed,0x4c,0xf1,0x00,0xe9,0xf3,0x69,0xe3,0xbd,0x65,0x37,0x88,0x69,0x55,0xda,0x2b,0x0b,0x55,0x35,0x6b,0x3a,0x64,0x18,0x9a,0x9b };
    const uint8_t IV[] = { 0x8f,0x16,0xcb,0xa4,0x96,0xa6,0xf2,0x60,0x84,0xbc,0x20,0xfa,0x9c,0x7e,0x03,0xfa };
    const uint8_t PLAINTEXT[] = { 0xe6 };
    const uint8_t CIPHERTEXT[] = { 0xe7 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-50", "[CFB8][MCT][256][ENCRYPT][n50]") {
    const uint8_t KEY[] = { 0x00,0x36,0xdb,0x40,0x3d,0x77,0x89,0xc4,0x4e,0xf4,0x9f,0x49,0x02,0xd4,0x1c,0x73,0xab,0x54,0x5f,0xc9,0x25,0xf8,0x6a,0x1f,0x50,0xbb,0xe9,0x8c,0x0f,0x5c,0x93,0x7c };
    const uint8_t IV[] = { 0xce,0x63,0xd7,0xa0,0x70,0x22,0x41,0x14,0x05,0x8e,0x82,0xb6,0x6b,0x44,0x09,0xe7 };
    const uint8_t PLAINTEXT[] = { 0xce };
    const uint8_t CIPHERTEXT[] = { 0xfd };
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

TEST_CASE("CFB8MCT256-ENCRYPT-51", "[CFB8][MCT][256][ENCRYPT][n51]") {
    const uint8_t KEY[] = { 0x7f,0x24,0x92,0xf7,0x0d,0x04,0x9e,0xb1,0x1e,0x07,0xfe,0x7f,0xbd,0x70,0xa6,0x54,0x3e,0x9b,0xc5,0x91,0x44,0xd2,0x1c,0xf5,0x7f,0x7c,0x16,0x75,0x93,0x42,0x6a,0x81 };
    const uint8_t IV[] = { 0x95,0xcf,0x9a,0x58,0x61,0x2a,0x76,0xea,0x2f,0xc7,0xff,0xf9,0x9c,0x1e,0xf9,0xfd };
    const uint8_t PLAINTEXT[] = { 0x27 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-52", "[CFB8][MCT][256][ENCRYPT][n52]") {
    const uint8_t KEY[] = { 0xc1,0x8b,0xb9,0xd8,0xf7,0xc6,0xd3,0xdb,0x97,0x5b,0x94,0x0e,0xff,0xbd,0x79,0x2e,0x2f,0x82,0xad,0xb6,0x28,0x38,0x45,0x0a,0xe3,0x2e,0x53,0xcf,0xd3,0x92,0x32,0x91 };
    const uint8_t IV[] = { 0x11,0x19,0x68,0x27,0x6c,0xea,0x59,0xff,0x9c,0x52,0x45,0xba,0x40,0xd0,0x58,0x10 };
    const uint8_t PLAINTEXT[] = { 0x7a };
    const uint8_t CIPHERTEXT[] = { 0x1b };
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

TEST_CASE("CFB8MCT256-ENCRYPT-53", "[CFB8][MCT][256][ENCRYPT][n53]") {
    const uint8_t KEY[] = { 0xfc,0x51,0x49,0xa4,0x88,0x9f,0xd9,0x72,0xe8,0x35,0xb9,0xf5,0x3c,0xfa,0x6f,0x86,0x4f,0x4b,0xc2,0x96,0x17,0xba,0xcd,0xbf,0xa4,0xd4,0x85,0xb3,0x5c,0x27,0x52,0x8a };
    const uint8_t IV[] = { 0x60,0xc9,0x6f,0x20,0x3f,0x82,0x88,0xb5,0x47,0xfa,0xd6,0x7c,0x8f,0xb5,0x60,0x1b };
    const uint8_t PLAINTEXT[] = { 0xa8 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-54", "[CFB8][MCT][256][ENCRYPT][n54]") {
    const uint8_t KEY[] = { 0x36,0x00,0x9a,0xd1,0xa8,0xcf,0x9f,0x27,0xd5,0x70,0x0d,0xfe,0x80,0x0f,0xf5,0x3e,0x78,0x1f,0xd7,0x4b,0xba,0x32,0xd9,0x3c,0xf4,0xe3,0x12,0xb4,0x99,0x50,0x0a,0x66 };
    const uint8_t IV[] = { 0x37,0x54,0x15,0xdd,0xad,0x88,0x14,0x83,0x50,0x37,0x97,0x07,0xc5,0x77,0x58,0xec };
    const uint8_t PLAINTEXT[] = { 0xb8 };
    const uint8_t CIPHERTEXT[] = { 0x42 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-55", "[CFB8][MCT][256][ENCRYPT][n55]") {
    const uint8_t KEY[] = { 0x46,0x14,0x22,0x82,0x01,0xa2,0x9d,0x6a,0x96,0x48,0x7c,0xfa,0x58,0xef,0x5c,0xdc,0xa6,0xaa,0x55,0xa0,0xf7,0xa4,0x22,0x18,0xe8,0xe1,0x0f,0xbd,0xb9,0x7c,0x24,0x24 };
    const uint8_t IV[] = { 0xde,0xb5,0x82,0xeb,0x4d,0x96,0xfb,0x24,0x1c,0x02,0x1d,0x09,0x20,0x2c,0x2e,0x42 };
    const uint8_t PLAINTEXT[] = { 0xe2 };
    const uint8_t CIPHERTEXT[] = { 0xf7 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-56", "[CFB8][MCT][256][ENCRYPT][n56]") {
    const uint8_t KEY[] = { 0x41,0xf5,0xe3,0xef,0xd3,0xac,0x66,0xbb,0xa1,0xf8,0x18,0x49,0x41,0x5a,0x6e,0x7f,0x25,0xe0,0x95,0xad,0xdb,0xdb,0xd4,0x19,0x61,0x1e,0xf8,0x31,0xd9,0x84,0xd8,0xd3 };
    const uint8_t IV[] = { 0x83,0x4a,0xc0,0x0d,0x2c,0x7f,0xf6,0x01,0x89,0xff,0xf7,0x8c,0x60,0xf8,0xfc,0xf7 };
    const uint8_t PLAINTEXT[] = { 0xa3 };
    const uint8_t CIPHERTEXT[] = { 0x31 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-57", "[CFB8][MCT][256][ENCRYPT][n57]") {
    const uint8_t KEY[] = { 0x1c,0xe9,0x02,0xa1,0xfb,0x00,0x5c,0xb4,0x56,0x4d,0x9e,0x98,0xb6,0x9c,0x59,0x94,0xf6,0xd9,0xfc,0xe6,0xdf,0xf7,0x45,0xa1,0x31,0x01,0x14,0x1a,0x65,0xbe,0xcd,0xe2 };
    const uint8_t IV[] = { 0xd3,0x39,0x69,0x4b,0x04,0x2c,0x91,0xb8,0x50,0x1f,0xec,0x2b,0xbc,0x3a,0x15,0x31 };
    const uint8_t PLAINTEXT[] = { 0xeb };
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

TEST_CASE("CFB8MCT256-ENCRYPT-58", "[CFB8][MCT][256][ENCRYPT][n58]") {
    const uint8_t KEY[] = { 0x96,0x12,0xd2,0x09,0x2d,0x7d,0x94,0xe4,0xd4,0x65,0xa0,0x1b,0x5b,0x72,0x8c,0x8e,0x01,0xcf,0xf3,0x96,0xcc,0x74,0xfd,0x05,0x09,0xf5,0x3d,0x88,0x8d,0x94,0x4b,0xb6 };
    const uint8_t IV[] = { 0xf7,0x16,0x0f,0x70,0x13,0x83,0xb8,0xa4,0x38,0xf4,0x29,0x92,0xe8,0x2a,0x86,0x54 };
    const uint8_t PLAINTEXT[] = { 0x1a };
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

TEST_CASE("CFB8MCT256-ENCRYPT-59", "[CFB8][MCT][256][ENCRYPT][n59]") {
    const uint8_t KEY[] = { 0xd8,0x9a,0x89,0x9e,0xe5,0x9c,0x9d,0x8b,0x11,0x2c,0x71,0x2b,0x3d,0x2f,0x07,0xe1,0x60,0xc8,0x0b,0x47,0x9f,0x8f,0x11,0xc1,0x40,0x8d,0x33,0x16,0x97,0x72,0xf3,0x7b };
    const uint8_t IV[] = { 0x61,0x07,0xf8,0xd1,0x53,0xfb,0xec,0xc4,0x49,0x78,0x0e,0x9e,0x1a,0xe6,0xb8,0xcd };
    const uint8_t PLAINTEXT[] = { 0x6f };
    const uint8_t CIPHERTEXT[] = { 0xce };
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

TEST_CASE("CFB8MCT256-ENCRYPT-60", "[CFB8][MCT][256][ENCRYPT][n60]") {
    const uint8_t KEY[] = { 0xa0,0x85,0x21,0xc5,0xdf,0x65,0xfc,0xda,0xd8,0xe4,0x3c,0xb8,0x81,0xc2,0x1b,0x3a,0x6e,0x21,0x2b,0xeb,0x78,0x20,0xc3,0x77,0x68,0x50,0x9f,0x01,0x96,0xf1,0xf1,0xb5 };
    const uint8_t IV[] = { 0x0e,0xe9,0x20,0xac,0xe7,0xaf,0xd2,0xb6,0x28,0xdd,0xac,0x17,0x01,0x83,0x02,0xce };
    const uint8_t PLAINTEXT[] = { 0xdb };
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

TEST_CASE("CFB8MCT256-ENCRYPT-61", "[CFB8][MCT][256][ENCRYPT][n61]") {
    const uint8_t KEY[] = { 0xb9,0x53,0x3c,0x6d,0xa3,0xfe,0xbe,0x32,0x83,0xb2,0x5b,0x94,0x43,0x41,0x95,0x0f,0xb6,0xbf,0xfe,0xa4,0x86,0x06,0x93,0x26,0xc8,0x0c,0xc3,0x6e,0xc0,0xd5,0xb5,0xf4 };
    const uint8_t IV[] = { 0xd8,0x9e,0xd5,0x4f,0xfe,0x26,0x50,0x51,0xa0,0x5c,0x5c,0x6f,0x56,0x24,0x44,0x41 };
    const uint8_t PLAINTEXT[] = { 0x35 };
    const uint8_t CIPHERTEXT[] = { 0xa5 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-62", "[CFB8][MCT][256][ENCRYPT][n62]") {
    const uint8_t KEY[] = { 0xc5,0xa0,0xf8,0xc7,0x26,0x08,0x42,0xc4,0xe0,0x6d,0x92,0xbe,0xfd,0x24,0x0b,0x55,0xfc,0xb2,0x69,0x58,0xd2,0x96,0x00,0xfc,0x30,0x16,0xfc,0xed,0xd1,0xfa,0x5d,0x51 };
    const uint8_t IV[] = { 0x4a,0x0d,0x97,0xfc,0x54,0x90,0x93,0xda,0xf8,0x1a,0x3f,0x83,0x11,0x2f,0xe8,0xa5 };
    const uint8_t PLAINTEXT[] = { 0x5a };
    const uint8_t CIPHERTEXT[] = { 0x0a };
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

TEST_CASE("CFB8MCT256-ENCRYPT-63", "[CFB8][MCT][256][ENCRYPT][n63]") {
    const uint8_t KEY[] = { 0xe3,0x49,0x5e,0x5d,0xe1,0x08,0x98,0x43,0xd2,0x42,0xdd,0x93,0x44,0x36,0x85,0x2f,0x94,0x61,0x18,0x6f,0x3e,0x5e,0xb0,0x3a,0xec,0x0f,0x9b,0x53,0x62,0xab,0x57,0x5b };
    const uint8_t IV[] = { 0x68,0xd3,0x71,0x37,0xec,0xc8,0xb0,0xc6,0xdc,0x19,0x67,0xbe,0xb3,0x51,0x0a,0x0a };
    const uint8_t PLAINTEXT[] = { 0x7a };
    const uint8_t CIPHERTEXT[] = { 0x19 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-64", "[CFB8][MCT][256][ENCRYPT][n64]") {
    const uint8_t KEY[] = { 0x68,0x5d,0x7e,0xab,0xd4,0x0b,0x45,0x6e,0xe5,0xc3,0xb4,0xf0,0xd6,0xfc,0x0c,0x51,0xee,0x83,0xcc,0x4f,0x8f,0x14,0x86,0xf7,0x3b,0x7c,0x59,0x55,0x27,0x11,0xaf,0x42 };
    const uint8_t IV[] = { 0x7a,0xe2,0xd4,0x20,0xb1,0x4a,0x36,0xcd,0xd7,0x73,0xc2,0x06,0x45,0xba,0xf8,0x19 };
    const uint8_t PLAINTEXT[] = { 0x7e };
    const uint8_t CIPHERTEXT[] = { 0xf4 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-65", "[CFB8][MCT][256][ENCRYPT][n65]") {
    const uint8_t KEY[] = { 0x72,0x3f,0x55,0xf8,0xe4,0xf6,0x01,0x6e,0x2d,0x2d,0xa2,0xb2,0xce,0xae,0xcf,0xcb,0xf3,0xc1,0x55,0x16,0x27,0x95,0x0a,0xa4,0xb1,0x2f,0xd8,0x5a,0xb0,0xc1,0xb8,0xb6 };
    const uint8_t IV[] = { 0x1d,0x42,0x99,0x59,0xa8,0x81,0x8c,0x53,0x8a,0x53,0x81,0x0f,0x97,0xd0,0x17,0xf4 };
    const uint8_t PLAINTEXT[] = { 0x9a };
    const uint8_t CIPHERTEXT[] = { 0x35 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-66", "[CFB8][MCT][256][ENCRYPT][n66]") {
    const uint8_t KEY[] = { 0xf1,0x05,0xd6,0x8e,0x9f,0xf5,0x20,0x9d,0x4d,0x57,0xc2,0x3c,0x2c,0xb2,0xf6,0x2a,0x93,0x86,0xd3,0x04,0xf6,0x18,0x86,0x89,0x87,0xf1,0xc2,0xd3,0xc2,0x70,0x95,0x83 };
    const uint8_t IV[] = { 0x60,0x47,0x86,0x12,0xd1,0x8d,0x8c,0x2d,0x36,0xde,0x1a,0x89,0x72,0xb1,0x2d,0x35 };
    const uint8_t PLAINTEXT[] = { 0xe1 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-67", "[CFB8][MCT][256][ENCRYPT][n67]") {
    const uint8_t KEY[] = { 0x44,0x77,0xa5,0xfe,0x47,0x66,0xc4,0xe9,0x9f,0x81,0x0d,0xae,0xc4,0xab,0x70,0x26,0x85,0x99,0x09,0xe7,0x2c,0x0a,0xf6,0x8f,0xfe,0x50,0xf4,0xaf,0x10,0x9f,0x8e,0xd7 };
    const uint8_t IV[] = { 0x16,0x1f,0xda,0xe3,0xda,0x12,0x70,0x06,0x79,0xa1,0x36,0x7c,0xd2,0xef,0x1b,0x54 };
    const uint8_t PLAINTEXT[] = { 0x0c };
    const uint8_t CIPHERTEXT[] = { 0x07 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-68", "[CFB8][MCT][256][ENCRYPT][n68]") {
    const uint8_t KEY[] = { 0x86,0x9a,0x2c,0xde,0x15,0x18,0x28,0x8a,0x3d,0x19,0x13,0x0f,0x03,0x07,0x00,0x32,0x0e,0xc4,0x44,0xbd,0x09,0x60,0xfc,0xc4,0x42,0x85,0xad,0x12,0xed,0x50,0xa4,0xd0 };
    const uint8_t IV[] = { 0x8b,0x5d,0x4d,0x5a,0x25,0x6a,0x0a,0x4b,0xbc,0xd5,0x59,0xbd,0xfd,0xcf,0x2a,0x07 };
    const uint8_t PLAINTEXT[] = { 0x14 };
    const uint8_t CIPHERTEXT[] = { 0x7c };
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

TEST_CASE("CFB8MCT256-ENCRYPT-69", "[CFB8][MCT][256][ENCRYPT][n69]") {
    const uint8_t KEY[] = { 0x0a,0x65,0x83,0x58,0x27,0x16,0xe2,0x34,0x42,0x02,0x46,0x68,0x6d,0x20,0x12,0x75,0xba,0x50,0x70,0x20,0x09,0x59,0xb4,0x29,0x3d,0xe4,0xd2,0x0b,0x5c,0x89,0xdf,0xac };
    const uint8_t IV[] = { 0xb4,0x94,0x34,0x9d,0x00,0x39,0x48,0xed,0x7f,0x61,0x7f,0x19,0xb1,0xd9,0x7b,0x7c };
    const uint8_t PLAINTEXT[] = { 0x47 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-70", "[CFB8][MCT][256][ENCRYPT][n70]") {
    const uint8_t KEY[] = { 0xdc,0x96,0x15,0xd6,0xbd,0xb8,0x40,0x26,0x08,0xc8,0xf4,0x88,0xe4,0x54,0xaf,0x4d,0xed,0x57,0x9e,0x65,0xdb,0xed,0x45,0x8a,0x59,0x7c,0x13,0xbc,0xd4,0x8c,0xb5,0x92 };
    const uint8_t IV[] = { 0x57,0x07,0xee,0x45,0xd2,0xb4,0xf1,0xa3,0x64,0x98,0xc1,0xb7,0x88,0x05,0x6a,0x3e };
    const uint8_t PLAINTEXT[] = { 0x38 };
    const uint8_t CIPHERTEXT[] = { 0x02 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-71", "[CFB8][MCT][256][ENCRYPT][n71]") {
    const uint8_t KEY[] = { 0x90,0xf0,0x25,0xcd,0x56,0xa4,0x0d,0x1f,0xbc,0xbe,0xe6,0xfc,0xdb,0xef,0x15,0x85,0xea,0x07,0xb9,0x93,0x83,0xd0,0xac,0x49,0x3b,0x00,0x69,0xfd,0x37,0xd2,0x60,0x90 };
    const uint8_t IV[] = { 0x07,0x50,0x27,0xf6,0x58,0x3d,0xe9,0xc3,0x62,0x7c,0x7a,0x41,0xe3,0x5e,0xd5,0x02 };
    const uint8_t PLAINTEXT[] = { 0xc8 };
    const uint8_t CIPHERTEXT[] = { 0xc7 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-72", "[CFB8][MCT][256][ENCRYPT][n72]") {
    const uint8_t KEY[] = { 0x49,0x3d,0xa3,0x5f,0x4e,0x3f,0x74,0x31,0x16,0x25,0x6b,0x0b,0xba,0x21,0xbb,0xd9,0xe2,0xe1,0xe0,0x1b,0x7b,0xbd,0x14,0x11,0xe4,0xa1,0xc1,0x01,0x5c,0x6e,0x60,0x57 };
    const uint8_t IV[] = { 0x08,0xe6,0x59,0x88,0xf8,0x6d,0xb8,0x58,0xdf,0xa1,0xa8,0xfc,0x6b,0xbc,0x00,0xc7 };
    const uint8_t PLAINTEXT[] = { 0x5c };
    const uint8_t CIPHERTEXT[] = { 0xe7 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-73", "[CFB8][MCT][256][ENCRYPT][n73]") {
    const uint8_t KEY[] = { 0x62,0x02,0xb0,0xd2,0xd9,0x43,0x1d,0x33,0x2c,0xce,0xf4,0xbb,0xa1,0x25,0x13,0x3d,0x51,0x64,0x8c,0x90,0xe0,0x2f,0x94,0x35,0xea,0xb5,0x8e,0x98,0xaf,0x47,0x2c,0xb0 };
    const uint8_t IV[] = { 0xb3,0x85,0x6c,0x8b,0x9b,0x92,0x80,0x24,0x0e,0x14,0x4f,0x99,0xf3,0x29,0x4c,0xe7 };
    const uint8_t PLAINTEXT[] = { 0xe4 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-74", "[CFB8][MCT][256][ENCRYPT][n74]") {
    const uint8_t KEY[] = { 0xd2,0xeb,0x43,0xf4,0x0e,0xb3,0x47,0x66,0x2b,0x93,0x97,0xda,0x19,0x71,0xd6,0xfb,0x8e,0xb2,0x9d,0xf2,0x09,0xc5,0xfe,0xe9,0xa0,0x30,0xb4,0x21,0xe8,0x7e,0xee,0x5e };
    const uint8_t IV[] = { 0xdf,0xd6,0x11,0x62,0xe9,0xea,0x6a,0xdc,0x4a,0x85,0x3a,0xb9,0x47,0x39,0xc2,0xee };
    const uint8_t PLAINTEXT[] = { 0xc6 };
    const uint8_t CIPHERTEXT[] = { 0x2c };
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

TEST_CASE("CFB8MCT256-ENCRYPT-75", "[CFB8][MCT][256][ENCRYPT][n75]") {
    const uint8_t KEY[] = { 0x33,0x30,0xd1,0x55,0xfa,0xfa,0x69,0xfb,0x2e,0xf3,0x8e,0x5b,0x62,0x68,0x2e,0x47,0xe7,0x34,0xb8,0x4b,0xa8,0x26,0xa9,0x53,0xbf,0x07,0x87,0x44,0xb1,0x21,0xd5,0x72 };
    const uint8_t IV[] = { 0x69,0x86,0x25,0xb9,0xa1,0xe3,0x57,0xba,0x1f,0x37,0x33,0x65,0x59,0x5f,0x3b,0x2c };
    const uint8_t PLAINTEXT[] = { 0xbc };
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

TEST_CASE("CFB8MCT256-ENCRYPT-76", "[CFB8][MCT][256][ENCRYPT][n76]") {
    const uint8_t KEY[] = { 0x41,0x63,0x14,0x44,0x67,0x26,0xa5,0x73,0xbc,0x48,0xc2,0xe0,0x10,0x97,0x5e,0xa6,0xc7,0xe3,0x8e,0xa6,0x27,0xf9,0xbd,0x73,0xec,0x8b,0x53,0x38,0x3a,0x48,0xb8,0xe3 };
    const uint8_t IV[] = { 0x20,0xd7,0x36,0xed,0x8f,0xdf,0x14,0x20,0x53,0x8c,0xd4,0x7c,0x8b,0x69,0x6d,0x91 };
    const uint8_t PLAINTEXT[] = { 0xe1 };
    const uint8_t CIPHERTEXT[] = { 0x7e };
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

TEST_CASE("CFB8MCT256-ENCRYPT-77", "[CFB8][MCT][256][ENCRYPT][n77]") {
    const uint8_t KEY[] = { 0x80,0xd1,0x21,0x17,0x5c,0xb2,0xe7,0xc1,0x72,0xa1,0x2f,0xfc,0x3e,0xaf,0x68,0x07,0xbc,0x0a,0x81,0x3b,0x96,0x8b,0x6a,0xb6,0xbf,0x52,0xec,0x88,0x3f,0x8e,0x5a,0x9d };
    const uint8_t IV[] = { 0x7b,0xe9,0x0f,0x9d,0xb1,0x72,0xd7,0xc5,0x53,0xd9,0xbf,0xb0,0x05,0xc6,0xe2,0x7e };
    const uint8_t PLAINTEXT[] = { 0xa1 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-78", "[CFB8][MCT][256][ENCRYPT][n78]") {
    const uint8_t KEY[] = { 0x3c,0x7b,0x2b,0xc6,0xc7,0x3d,0x86,0x96,0x67,0xc7,0xa1,0xbf,0x7f,0x90,0x0a,0x7b,0xd4,0x4d,0x39,0xaf,0x5d,0xbb,0xeb,0x79,0x0e,0xf0,0xa0,0x63,0xa4,0x68,0x17,0x7f };
    const uint8_t IV[] = { 0x68,0x47,0xb8,0x94,0xcb,0x30,0x81,0xcf,0xb1,0xa2,0x4c,0xeb,0x9b,0xe6,0x4d,0xe2 };
    const uint8_t PLAINTEXT[] = { 0x7c };
    const uint8_t CIPHERTEXT[] = { 0x38 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-79", "[CFB8][MCT][256][ENCRYPT][n79]") {
    const uint8_t KEY[] = { 0xbd,0xe4,0x86,0xfe,0xa9,0x89,0x1c,0x23,0xfe,0xb8,0x1a,0x78,0xdd,0x4c,0x17,0xd7,0xf4,0x71,0x4b,0xce,0xac,0x73,0x19,0x4c,0x8d,0xc5,0xe5,0x34,0x98,0x95,0xf1,0x47 };
    const uint8_t IV[] = { 0x20,0x3c,0x72,0x61,0xf1,0xc8,0xf2,0x35,0x83,0x35,0x45,0x57,0x3c,0xfd,0xe6,0x38 };
    const uint8_t PLAINTEXT[] = { 0xac };
    const uint8_t CIPHERTEXT[] = { 0x67 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-80", "[CFB8][MCT][256][ENCRYPT][n80]") {
    const uint8_t KEY[] = { 0xdd,0xe2,0x8d,0xcf,0xee,0x78,0xf0,0x99,0x92,0x0a,0xf0,0xa3,0x92,0x94,0xce,0xf4,0xca,0x78,0x06,0x43,0x35,0x89,0x0d,0x37,0x9a,0x47,0x66,0xd5,0x0d,0x57,0xbb,0x20 };
    const uint8_t IV[] = { 0x3e,0x09,0x4d,0x8d,0x99,0xfa,0x14,0x7b,0x17,0x82,0x83,0xe1,0x95,0xc2,0x4a,0x67 };
    const uint8_t PLAINTEXT[] = { 0x23 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-81", "[CFB8][MCT][256][ENCRYPT][n81]") {
    const uint8_t KEY[] = { 0x3b,0xdd,0x11,0x34,0xe9,0x00,0xbd,0x8a,0x36,0x51,0xb0,0xea,0x92,0xb1,0xb0,0xa8,0x46,0xd8,0x03,0x41,0x57,0x59,0x8f,0x9c,0xe9,0x61,0x46,0x74,0x4e,0x31,0x0e,0xb5 };
    const uint8_t IV[] = { 0x8c,0xa0,0x05,0x02,0x62,0xd0,0x82,0xab,0x73,0x26,0x20,0xa1,0x43,0x66,0xb5,0x95 };
    const uint8_t PLAINTEXT[] = { 0x5c };
    const uint8_t CIPHERTEXT[] = { 0xcf };
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

TEST_CASE("CFB8MCT256-ENCRYPT-82", "[CFB8][MCT][256][ENCRYPT][n82]") {
    const uint8_t KEY[] = { 0x2c,0x5a,0xe3,0xb1,0x97,0xce,0xe9,0xfe,0x2c,0xf7,0x76,0x1b,0x9d,0x26,0x45,0xb2,0x31,0xdf,0x42,0x22,0x2e,0x29,0xf2,0xac,0xc9,0x0e,0x56,0xb0,0x2d,0x7e,0x70,0x7a };
    const uint8_t IV[] = { 0x77,0x07,0x41,0x63,0x79,0x70,0x7d,0x30,0x20,0x6f,0x10,0xc4,0x63,0x4f,0x7e,0xcf };
    const uint8_t PLAINTEXT[] = { 0x1a };
    const uint8_t CIPHERTEXT[] = { 0x79 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-83", "[CFB8][MCT][256][ENCRYPT][n83]") {
    const uint8_t KEY[] = { 0x91,0x9b,0xe1,0xbe,0xed,0x4b,0xdf,0xd2,0xda,0x73,0x21,0xab,0xf0,0x75,0xe2,0x2b,0x97,0xfb,0x22,0x93,0x28,0xf0,0x63,0xb3,0x27,0x54,0x25,0x4d,0xbe,0xe3,0x9f,0x03 };
    const uint8_t IV[] = { 0xa6,0x24,0x60,0xb1,0x06,0xd9,0x91,0x1f,0xee,0x5a,0x73,0xfd,0x93,0x9d,0xef,0x79 };
    const uint8_t PLAINTEXT[] = { 0x99 };
    const uint8_t CIPHERTEXT[] = { 0xa9 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-84", "[CFB8][MCT][256][ENCRYPT][n84]") {
    const uint8_t KEY[] = { 0x3f,0x3d,0x75,0x3e,0xb2,0xd2,0x8f,0x13,0x04,0x5a,0xc8,0xa1,0x4f,0xc5,0x12,0x3f,0x39,0x96,0x6b,0x9e,0xa1,0x1f,0xfd,0xbb,0xc5,0x7d,0xf4,0x92,0x09,0xd1,0x4f,0xaa };
    const uint8_t IV[] = { 0xae,0x6d,0x49,0x0d,0x89,0xef,0x9e,0x08,0xe2,0x29,0xd1,0xdf,0xb7,0x32,0xd0,0xa9 };
    const uint8_t PLAINTEXT[] = { 0x14 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-85", "[CFB8][MCT][256][ENCRYPT][n85]") {
    const uint8_t KEY[] = { 0x2d,0xbe,0xb4,0xd3,0xde,0xac,0xf5,0xa7,0x19,0x0e,0xf4,0x0b,0xc4,0x9b,0x65,0xe2,0x3f,0x2b,0x88,0xb8,0x9d,0xb4,0xff,0x1b,0xcc,0x6d,0x2a,0x0b,0xe4,0xe6,0xf9,0xc9 };
    const uint8_t IV[] = { 0x06,0xbd,0xe3,0x26,0x3c,0xab,0x02,0xa0,0x09,0x10,0xde,0x99,0xed,0x37,0xb6,0x63 };
    const uint8_t PLAINTEXT[] = { 0xdd };
    const uint8_t CIPHERTEXT[] = { 0x89 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-86", "[CFB8][MCT][256][ENCRYPT][n86]") {
    const uint8_t KEY[] = { 0xcd,0xb2,0xcb,0x51,0xa3,0xf8,0x67,0x4e,0x2e,0x43,0xa2,0xc9,0xef,0xcb,0x58,0x63,0x62,0xdb,0x6c,0x62,0xc5,0x33,0xf3,0x44,0x7e,0xe8,0x10,0x06,0x17,0xaf,0x84,0x40 };
    const uint8_t IV[] = { 0x5d,0xf0,0xe4,0xda,0x58,0x87,0x0c,0x5f,0xb2,0x85,0x3a,0x0d,0xf3,0x49,0x7d,0x89 };
    const uint8_t PLAINTEXT[] = { 0x81 };
    const uint8_t CIPHERTEXT[] = { 0x94 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-87", "[CFB8][MCT][256][ENCRYPT][n87]") {
    const uint8_t KEY[] = { 0x62,0xe9,0x14,0x95,0x58,0xd2,0x68,0x25,0x34,0xff,0x71,0x6d,0x8d,0x05,0xe4,0xd6,0x09,0x57,0x16,0x49,0x96,0x66,0x40,0x79,0x39,0xab,0x35,0x0e,0xb3,0x1f,0x5d,0xd4 };
    const uint8_t IV[] = { 0x6b,0x8c,0x7a,0x2b,0x53,0x55,0xb3,0x3d,0x47,0x43,0x25,0x08,0xa4,0xb0,0xd9,0x94 };
    const uint8_t PLAINTEXT[] = { 0xb5 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-88", "[CFB8][MCT][256][ENCRYPT][n88]") {
    const uint8_t KEY[] = { 0x0f,0x6f,0x79,0x03,0xe9,0xd0,0x9c,0x81,0x09,0xb3,0x6e,0xe5,0x28,0x03,0x99,0x2d,0x53,0x0d,0xf3,0x04,0x76,0x37,0x69,0xfa,0xfd,0x2f,0x5a,0x16,0xb4,0xb9,0x05,0xf1 };
    const uint8_t IV[] = { 0x5a,0x5a,0xe5,0x4d,0xe0,0x51,0x29,0x83,0xc4,0x84,0x6f,0x18,0x07,0xa6,0x58,0x25 };
    const uint8_t PLAINTEXT[] = { 0xfb };
    const uint8_t CIPHERTEXT[] = { 0x93 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-89", "[CFB8][MCT][256][ENCRYPT][n89]") {
    const uint8_t KEY[] = { 0xd4,0x36,0x01,0x91,0x10,0x84,0x5b,0x40,0x92,0x6a,0xb1,0xf8,0xa4,0x0f,0xea,0xa4,0x9d,0x97,0x80,0xc3,0x62,0xdc,0x6c,0x54,0x0e,0xb9,0x65,0x38,0x95,0x81,0xe5,0x62 };
    const uint8_t IV[] = { 0xce,0x9a,0x73,0xc7,0x14,0xeb,0x05,0xae,0xf3,0x96,0x3f,0x2e,0x21,0x38,0xe0,0x93 };
    const uint8_t PLAINTEXT[] = { 0x89 };
    const uint8_t CIPHERTEXT[] = { 0x16 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-90", "[CFB8][MCT][256][ENCRYPT][n90]") {
    const uint8_t KEY[] = { 0xcf,0xff,0x36,0x77,0xf0,0x82,0x49,0x3a,0xb4,0x9f,0xbb,0x5b,0x14,0xf0,0x33,0x9b,0x28,0x49,0xae,0x09,0x0c,0x54,0xe3,0x71,0xe5,0x7a,0x2f,0xe0,0x93,0xfa,0x87,0x74 };
    const uint8_t IV[] = { 0xb5,0xde,0x2e,0xca,0x6e,0x88,0x8f,0x25,0xeb,0xc3,0x4a,0xd8,0x06,0x7b,0x62,0x16 };
    const uint8_t PLAINTEXT[] = { 0x3f };
    const uint8_t CIPHERTEXT[] = { 0x6e };
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

TEST_CASE("CFB8MCT256-ENCRYPT-91", "[CFB8][MCT][256][ENCRYPT][n91]") {
    const uint8_t KEY[] = { 0x55,0x27,0x65,0x7d,0x98,0x65,0x87,0x84,0xe6,0xd1,0x16,0x03,0x79,0x35,0x04,0x93,0x56,0x2e,0x3f,0xa6,0xac,0x10,0xcf,0x7f,0x2a,0xc2,0x37,0x37,0xf4,0xb7,0x26,0x1a };
    const uint8_t IV[] = { 0x7e,0x67,0x91,0xaf,0xa0,0x44,0x2c,0x0e,0xcf,0xb8,0x18,0xd7,0x67,0x4d,0xa1,0x6e };
    const uint8_t PLAINTEXT[] = { 0x08 };
    const uint8_t CIPHERTEXT[] = { 0xd8 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-92", "[CFB8][MCT][256][ENCRYPT][n92]") {
    const uint8_t KEY[] = { 0x17,0x44,0x9e,0xca,0xa0,0x42,0xad,0xff,0x2b,0x24,0x11,0x18,0x31,0x1d,0x21,0xb1,0xc8,0xc5,0x1b,0xd0,0x60,0xaf,0x90,0xf3,0xc8,0xec,0x94,0x19,0xae,0x59,0xc9,0xc2 };
    const uint8_t IV[] = { 0x9e,0xeb,0x24,0x76,0xcc,0xbf,0x5f,0x8c,0xe2,0x2e,0xa3,0x2e,0x5a,0xee,0xef,0xd8 };
    const uint8_t PLAINTEXT[] = { 0x22 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-93", "[CFB8][MCT][256][ENCRYPT][n93]") {
    const uint8_t KEY[] = { 0x60,0x07,0x1b,0x6c,0xdb,0x63,0x7c,0xb3,0xec,0x25,0x91,0x5a,0x63,0xda,0x20,0xed,0xf1,0xe0,0x7b,0xde,0xc2,0xcf,0x46,0xa0,0xac,0x54,0x37,0x6e,0xac,0x81,0xa6,0xe7 };
    const uint8_t IV[] = { 0x39,0x25,0x60,0x0e,0xa2,0x60,0xd6,0x53,0x64,0xb8,0xa3,0x77,0x02,0xd8,0x6f,0x25 };
    const uint8_t PLAINTEXT[] = { 0x5c };
    const uint8_t CIPHERTEXT[] = { 0x7c };
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

TEST_CASE("CFB8MCT256-ENCRYPT-94", "[CFB8][MCT][256][ENCRYPT][n94]") {
    const uint8_t KEY[] = { 0x03,0x1a,0x57,0xf6,0x48,0x5a,0x28,0x77,0x2d,0x0b,0xf1,0x6d,0x42,0x40,0xbb,0x61,0x69,0x4c,0xbd,0x02,0xa1,0x38,0x32,0x39,0x04,0x57,0xf4,0xd1,0x53,0x7d,0xbb,0x9b };
    const uint8_t IV[] = { 0x98,0xac,0xc6,0xdc,0x63,0xf7,0x74,0x99,0xa8,0x03,0xc3,0xbf,0xff,0xfc,0x1d,0x7c };
    const uint8_t PLAINTEXT[] = { 0x8c };
    const uint8_t CIPHERTEXT[] = { 0xce };
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

TEST_CASE("CFB8MCT256-ENCRYPT-95", "[CFB8][MCT][256][ENCRYPT][n95]") {
    const uint8_t KEY[] = { 0x87,0x4e,0x71,0x88,0x88,0xb7,0x75,0xed,0x4a,0xc1,0xd4,0x85,0xa6,0x00,0x72,0x53,0xe1,0xc0,0x00,0x47,0x1a,0x0e,0xf5,0xf1,0xc7,0xb6,0x34,0x74,0xb7,0x6e,0x5a,0x55 };
    const uint8_t IV[] = { 0x88,0x8c,0xbd,0x45,0xbb,0x36,0xc7,0xc8,0xc3,0xe1,0xc0,0xa5,0xe4,0x13,0xe1,0xce };
    const uint8_t PLAINTEXT[] = { 0x32 };
    const uint8_t CIPHERTEXT[] = { 0x38 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-96", "[CFB8][MCT][256][ENCRYPT][n96]") {
    const uint8_t KEY[] = { 0xc6,0x1e,0xd5,0xab,0xee,0x0c,0x44,0x5e,0xa2,0x4c,0x77,0xdf,0xa3,0xc4,0x34,0xe0,0x91,0x5f,0xe9,0xc7,0x5b,0xac,0xd2,0xb1,0x7c,0x21,0x06,0xed,0x6b,0xbc,0xdb,0x6d };
    const uint8_t IV[] = { 0x70,0x9f,0xe9,0x80,0x41,0xa2,0x27,0x40,0xbb,0x97,0x32,0x99,0xdc,0xd2,0x81,0x38 };
    const uint8_t PLAINTEXT[] = { 0xb3 };
    const uint8_t CIPHERTEXT[] = { 0xdd };
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

TEST_CASE("CFB8MCT256-ENCRYPT-97", "[CFB8][MCT][256][ENCRYPT][n97]") {
    const uint8_t KEY[] = { 0x89,0xce,0x93,0x5b,0x83,0xdd,0x31,0xcf,0xf6,0x38,0x92,0x9f,0x4e,0x3b,0x29,0x30,0x39,0x58,0x3c,0x79,0x2d,0xdf,0x40,0xc8,0x95,0xe7,0xa0,0xe0,0x75,0x1b,0x54,0xb0 };
    const uint8_t IV[] = { 0xa8,0x07,0xd5,0xbe,0x76,0x73,0x92,0x79,0xe9,0xc6,0xa6,0x0d,0x1e,0xa7,0x8f,0xdd };
    const uint8_t PLAINTEXT[] = { 0xd0 };
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

TEST_CASE("CFB8MCT256-ENCRYPT-98", "[CFB8][MCT][256][ENCRYPT][n98]") {
    const uint8_t KEY[] = { 0xe7,0x3b,0x42,0x46,0xac,0x3c,0x84,0x56,0x84,0x4d,0xba,0xbb,0x4c,0x8f,0xec,0x7c,0xee,0x49,0x3d,0x60,0xdd,0x10,0x66,0x50,0x3b,0xcb,0x7d,0xca,0x32,0xfe,0x6c,0xee };
    const uint8_t IV[] = { 0xd7,0x11,0x01,0x19,0xf0,0xcf,0x26,0x98,0xae,0x2c,0xdd,0x2a,0x47,0xe5,0x38,0x5e };
    const uint8_t PLAINTEXT[] = { 0x4c };
    const uint8_t CIPHERTEXT[] = { 0xab };
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

TEST_CASE("CFB8MCT256-ENCRYPT-99", "[CFB8][MCT][256][ENCRYPT][n99]") {
    const uint8_t KEY[] = { 0x96,0x49,0x32,0xe9,0xe5,0xe2,0xf2,0x34,0x52,0xe7,0xf0,0xc0,0xa8,0xa4,0xa4,0x6c,0x82,0xb6,0xea,0xc6,0x48,0x8b,0x21,0xc3,0x1a,0x88,0x1e,0x93,0xb5,0xed,0xf0,0x45 };
    const uint8_t IV[] = { 0x6c,0xff,0xd7,0xa6,0x95,0x9b,0x47,0x93,0x21,0x43,0x63,0x59,0x87,0x13,0x9c,0xab };
    const uint8_t PLAINTEXT[] = { 0x10 };
    const uint8_t CIPHERTEXT[] = { 0x46 };
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

TEST_CASE("CFB8MCT256-DECRYPT-0", "[CFB8][MCT][256][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0x39,0xb7,0x29,0x7f,0x2d,0x05,0x04,0xdc,0x87,0xe1,0xf4,0xc5,0xe2,0xca,0x8a,0x56,0x7c,0x58,0x0b,0x8d,0xe7,0x23,0xc5,0x51,0x02,0xe0,0xa3,0xb3,0x28,0xcd,0x00,0x73 };
    const uint8_t IV[] = { 0xff,0xe3,0xc1,0xb7,0x8e,0x92,0xe0,0x17,0x79,0xf2,0x9a,0x93,0x49,0xf7,0x6b,0xc8 };
    const uint8_t PLAINTEXT[] = { 0x2a };
    const uint8_t CIPHERTEXT[] = { 0xaa };
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

TEST_CASE("CFB8MCT256-DECRYPT-1", "[CFB8][MCT][256][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0x8d,0x1e,0x70,0x22,0x8d,0x5e,0xd3,0x15,0xcf,0x6c,0x23,0x5d,0x62,0x1e,0x51,0xc4,0x3c,0xf7,0x76,0x18,0x81,0xb8,0x47,0x15,0x8d,0x80,0x95,0xdb,0xba,0xd7,0x9d,0x59 };
    const uint8_t IV[] = { 0x40,0xaf,0x7d,0x95,0x66,0x9b,0x82,0x44,0x8f,0x60,0x36,0x68,0x92,0x1a,0x9d,0x2a };
    const uint8_t PLAINTEXT[] = { 0xda };
    const uint8_t CIPHERTEXT[] = { 0x92 };
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

TEST_CASE("CFB8MCT256-DECRYPT-2", "[CFB8][MCT][256][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0xde,0x52,0xc5,0x68,0x9b,0x41,0x11,0xda,0x6f,0xb7,0x71,0xd1,0x40,0xef,0xca,0xab,0x2c,0x6a,0x88,0x7b,0x7b,0x79,0xb0,0x60,0x75,0x06,0xf9,0x14,0x4f,0xfa,0x25,0x83 };
    const uint8_t IV[] = { 0x10,0x9d,0xfe,0x63,0xfa,0xc1,0xf7,0x75,0xf8,0x86,0x6c,0xcf,0xf5,0x2d,0xb8,0xda };
    const uint8_t PLAINTEXT[] = { 0x96 };
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

TEST_CASE("CFB8MCT256-DECRYPT-3", "[CFB8][MCT][256][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0x01,0x47,0x73,0x33,0x3a,0x47,0xbd,0x2e,0x06,0x2e,0x6b,0x37,0xa3,0x53,0x77,0x8c,0x52,0x30,0xde,0xd3,0xc4,0xcb,0x36,0xfe,0xcc,0x69,0xce,0x19,0xa0,0x48,0xa8,0x15 };
    const uint8_t IV[] = { 0x7e,0x5a,0x56,0xa8,0xbf,0xb2,0x86,0x9e,0xb9,0x6f,0x37,0x0d,0xef,0xb2,0x8d,0x96 };
    const uint8_t PLAINTEXT[] = { 0x47 };
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

TEST_CASE("CFB8MCT256-DECRYPT-4", "[CFB8][MCT][256][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0x72,0xe6,0xc1,0x3a,0x6f,0x82,0xb3,0xa3,0x78,0x86,0xa5,0xbe,0x3d,0xc1,0xd7,0x22,0x9c,0x52,0x8c,0xde,0x62,0x08,0x78,0xf2,0xce,0x53,0x9c,0x23,0x35,0x5e,0x95,0x52 };
    const uint8_t IV[] = { 0xce,0x62,0x52,0x0d,0xa6,0xc3,0x4e,0x0c,0x02,0x3a,0x52,0x3a,0x95,0x16,0x3d,0x47 };
    const uint8_t PLAINTEXT[] = { 0xce };
    const uint8_t CIPHERTEXT[] = { 0xae };
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

TEST_CASE("CFB8MCT256-DECRYPT-5", "[CFB8][MCT][256][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0xb5,0xbd,0xd8,0x6b,0x70,0x82,0x96,0xb2,0xae,0xcd,0xfd,0x31,0xe6,0xf9,0x68,0x91,0x87,0xab,0x4a,0x50,0x5a,0x2a,0x35,0xb5,0xc9,0x67,0x9e,0x06,0x9f,0x74,0x99,0x9c };
    const uint8_t IV[] = { 0x1b,0xf9,0xc6,0x8e,0x38,0x22,0x4d,0x47,0x07,0x34,0x02,0x25,0xaa,0x2a,0x0c,0xce };
    const uint8_t PLAINTEXT[] = { 0x40 };
    const uint8_t CIPHERTEXT[] = { 0xb3 };
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

TEST_CASE("CFB8MCT256-DECRYPT-6", "[CFB8][MCT][256][DECRYPT][n6]") {
    const uint8_t KEY[] = { 0x53,0xca,0x08,0x08,0x22,0xb3,0xc6,0x3b,0xb8,0x75,0xa8,0xff,0x7a,0x06,0xba,0x84,0x54,0xad,0xb8,0x5b,0x73,0x8d,0x07,0xeb,0xf1,0x7c,0xfb,0xd3,0x95,0x7f,0x65,0xdc };
    const uint8_t IV[] = { 0xd3,0x06,0xf2,0x0b,0x29,0xa7,0x32,0x5e,0x38,0x1b,0x65,0xd5,0x0a,0x0b,0xfc,0x40 };
    const uint8_t PLAINTEXT[] = { 0x49 };
    const uint8_t CIPHERTEXT[] = { 0x15 };
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

TEST_CASE("CFB8MCT256-DECRYPT-7", "[CFB8][MCT][256][DECRYPT][n7]") {
    const uint8_t KEY[] = { 0x7e,0xa4,0xc5,0x30,0xd2,0xea,0xde,0xa3,0xa1,0x00,0x25,0xd3,0xed,0x91,0xd3,0x4a,0x73,0xd5,0x8b,0xd9,0xfa,0xed,0x04,0x7b,0x30,0x68,0xec,0x2d,0x10,0x74,0x54,0x95 };
    const uint8_t IV[] = { 0x27,0x78,0x33,0x82,0x89,0x60,0x03,0x90,0xc1,0x14,0x17,0xfe,0x85,0x0b,0x31,0x49 };
    const uint8_t PLAINTEXT[] = { 0xbf };
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

TEST_CASE("CFB8MCT256-DECRYPT-8", "[CFB8][MCT][256][DECRYPT][n8]") {
    const uint8_t KEY[] = { 0x01,0x2a,0xc3,0x6a,0x7f,0xdf,0xe5,0x46,0x2e,0xe9,0x7b,0x64,0xf0,0xf8,0x68,0x7d,0xc1,0x49,0x9a,0x95,0xe5,0x06,0x2a,0xc3,0xb2,0x7e,0x0d,0x50,0xd3,0xe5,0x30,0x2a };
    const uint8_t IV[] = { 0xb2,0x9c,0x11,0x4c,0x1f,0xeb,0x2e,0xb8,0x82,0x16,0xe1,0x7d,0xc3,0x91,0x64,0xbf };
    const uint8_t PLAINTEXT[] = { 0x65 };
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

TEST_CASE("CFB8MCT256-DECRYPT-9", "[CFB8][MCT][256][DECRYPT][n9]") {
    const uint8_t KEY[] = { 0xaf,0xf4,0xff,0x24,0xc3,0x5e,0x7e,0x8e,0x20,0xe7,0x8e,0x2c,0x13,0xc4,0x8e,0x2f,0x10,0x80,0xaf,0x43,0xb1,0x2c,0x87,0x99,0x87,0x5d,0xa1,0x4d,0x9d,0x24,0xca,0x4f };
    const uint8_t IV[] = { 0xd1,0xc9,0x35,0xd6,0x54,0x2a,0xad,0x5a,0x35,0x23,0xac,0x1d,0x4e,0xc1,0xfa,0x65 };
    const uint8_t PLAINTEXT[] = { 0x5b };
    const uint8_t CIPHERTEXT[] = { 0x52 };
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

TEST_CASE("CFB8MCT256-DECRYPT-10", "[CFB8][MCT][256][DECRYPT][n10]") {
    const uint8_t KEY[] = { 0x30,0x32,0x4a,0xcb,0xf2,0x7f,0xe7,0xed,0x14,0xf4,0x35,0x2d,0x15,0xee,0x51,0x5c,0x19,0x7b,0xa0,0x6a,0x1e,0x51,0x18,0xc4,0x2c,0x30,0xe1,0x57,0x00,0x22,0xce,0x14 };
    const uint8_t IV[] = { 0x09,0xfb,0x0f,0x29,0xaf,0x7d,0x9f,0x5d,0xab,0x6d,0x40,0x1a,0x9d,0x06,0x04,0x5b };
    const uint8_t PLAINTEXT[] = { 0x82 };
    const uint8_t CIPHERTEXT[] = { 0x73 };
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

TEST_CASE("CFB8MCT256-DECRYPT-11", "[CFB8][MCT][256][DECRYPT][n11]") {
    const uint8_t KEY[] = { 0x59,0x97,0x2e,0xbb,0x3f,0xdf,0x0b,0xb9,0x3e,0x45,0x42,0x62,0x51,0x16,0x1a,0x27,0xf4,0x40,0x70,0x93,0x4e,0xf5,0x45,0xfe,0x79,0x3a,0xb4,0x1f,0xb9,0x00,0x4f,0x96 };
    const uint8_t IV[] = { 0xed,0x3b,0xd0,0xf9,0x50,0xa4,0x5d,0x3a,0x55,0x0a,0x55,0x48,0xb9,0x22,0x81,0x82 };
    const uint8_t PLAINTEXT[] = { 0x71 };
    const uint8_t CIPHERTEXT[] = { 0x7b };
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

TEST_CASE("CFB8MCT256-DECRYPT-12", "[CFB8][MCT][256][DECRYPT][n12]") {
    const uint8_t KEY[] = { 0xf9,0x63,0x04,0xb0,0xbb,0x46,0x58,0xe3,0x58,0xf1,0x4d,0x20,0xdc,0x1c,0xd2,0x4f,0xc0,0x5c,0xa5,0xf9,0xf8,0x91,0xac,0xac,0x0d,0x73,0x47,0x97,0xc7,0xf7,0xfe,0xe7 };
    const uint8_t IV[] = { 0x34,0x1c,0xd5,0x6a,0xb6,0x64,0xe9,0x52,0x74,0x49,0xf3,0x88,0x7e,0xf7,0xb1,0x71 };
    const uint8_t PLAINTEXT[] = { 0x6d };
    const uint8_t CIPHERTEXT[] = { 0x68 };
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

TEST_CASE("CFB8MCT256-DECRYPT-13", "[CFB8][MCT][256][DECRYPT][n13]") {
    const uint8_t KEY[] = { 0x9a,0x9c,0xb8,0xf1,0xac,0x03,0xba,0x0e,0x1a,0x8b,0xe5,0x96,0xa7,0x4e,0x2e,0xe3,0x22,0xdb,0xe9,0x9d,0xd3,0x34,0x74,0xcb,0x9f,0x71,0xea,0x4e,0x50,0xba,0x27,0x8a };
    const uint8_t IV[] = { 0xe2,0x87,0x4c,0x64,0x2b,0xa5,0xd8,0x67,0x92,0x02,0xad,0xd9,0x97,0x4d,0xd9,0x6d };
    const uint8_t PLAINTEXT[] = { 0x8c };
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

TEST_CASE("CFB8MCT256-DECRYPT-14", "[CFB8][MCT][256][DECRYPT][n14]") {
    const uint8_t KEY[] = { 0xad,0xdb,0x7e,0xe4,0x5f,0x29,0xbe,0x77,0x2e,0xbd,0xdb,0x49,0xa6,0x67,0x38,0x2a,0x9c,0x0b,0xd2,0x73,0xd7,0x6e,0xe0,0x30,0xb0,0xea,0xbc,0x53,0xb3,0x89,0x0f,0x06 };
    const uint8_t IV[] = { 0xbe,0xd0,0x3b,0xee,0x04,0x5a,0x94,0xfb,0x2f,0x9b,0x56,0x1d,0xe3,0x33,0x28,0x8c };
    const uint8_t PLAINTEXT[] = { 0xd1 };
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

TEST_CASE("CFB8MCT256-DECRYPT-15", "[CFB8][MCT][256][DECRYPT][n15]") {
    const uint8_t KEY[] = { 0x6d,0xdb,0xdd,0x8f,0x78,0x5a,0x36,0xcf,0x01,0x14,0xee,0xb1,0x56,0xe7,0xae,0xd2,0x67,0x8d,0x64,0x26,0x30,0x2b,0x01,0xb8,0x77,0x2d,0x02,0x6e,0xef,0xbb,0xe6,0xd7 };
    const uint8_t IV[] = { 0xfb,0x86,0xb6,0x55,0xe7,0x45,0xe1,0x88,0xc7,0xc7,0xbe,0x3d,0x5c,0x32,0xe9,0xd1 };
    const uint8_t PLAINTEXT[] = { 0xd4 };
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

TEST_CASE("CFB8MCT256-DECRYPT-16", "[CFB8][MCT][256][DECRYPT][n16]") {
    const uint8_t KEY[] = { 0xb5,0x2b,0x24,0x8a,0x8b,0x1e,0x74,0x16,0x6c,0xdd,0x9c,0xfd,0xce,0x7c,0x6e,0x30,0x79,0xee,0xbe,0x05,0x90,0x5d,0xcf,0xb2,0x0d,0x2d,0x22,0x8b,0x9a,0xa4,0x1a,0x03 };
    const uint8_t IV[] = { 0x1e,0x63,0xda,0x23,0xa0,0x76,0xce,0x0a,0x7a,0x00,0x20,0xe5,0x75,0x1f,0xfc,0xd4 };
    const uint8_t PLAINTEXT[] = { 0xfe };
    const uint8_t CIPHERTEXT[] = { 0xe2 };
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

TEST_CASE("CFB8MCT256-DECRYPT-17", "[CFB8][MCT][256][DECRYPT][n17]") {
    const uint8_t KEY[] = { 0x71,0x10,0x9b,0x68,0x28,0x79,0x5b,0xb3,0x56,0x98,0x4b,0x8e,0x8a,0x3f,0x10,0x38,0xcb,0x99,0xe4,0x66,0xc2,0x9c,0x16,0xf1,0x57,0xae,0x9b,0x43,0xd4,0x04,0xe7,0xfd };
    const uint8_t IV[] = { 0xb2,0x77,0x5a,0x63,0x52,0xc1,0xd9,0x43,0x5a,0x83,0xb9,0xc8,0x4e,0xa0,0xfd,0xfe };
    const uint8_t PLAINTEXT[] = { 0xd1 };
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

TEST_CASE("CFB8MCT256-DECRYPT-18", "[CFB8][MCT][256][DECRYPT][n18]") {
    const uint8_t KEY[] = { 0x89,0x1f,0x3b,0xab,0xcd,0x87,0x26,0xfa,0x70,0x73,0xa7,0x2a,0x6a,0x32,0xb1,0x16,0x69,0x71,0xee,0x2c,0x8c,0x51,0x2c,0xf4,0x3d,0x83,0xbc,0x65,0x72,0x75,0x6b,0x2c };
    const uint8_t IV[] = { 0xa2,0xe8,0x0a,0x4a,0x4e,0xcd,0x3a,0x05,0x6a,0x2d,0x27,0x26,0xa6,0x71,0x8c,0xd1 };
    const uint8_t PLAINTEXT[] = { 0xcb };
    const uint8_t CIPHERTEXT[] = { 0x2e };
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

TEST_CASE("CFB8MCT256-DECRYPT-19", "[CFB8][MCT][256][DECRYPT][n19]") {
    const uint8_t KEY[] = { 0x18,0x65,0xcf,0xe7,0x63,0x8c,0x67,0xe6,0x41,0x0e,0x42,0x46,0x10,0x1e,0xfb,0xe9,0xd1,0x97,0x64,0x33,0x62,0x62,0x69,0x32,0xac,0x95,0x27,0xa8,0xee,0xcf,0xab,0xe7 };
    const uint8_t IV[] = { 0xb8,0xe6,0x8a,0x1f,0xee,0x33,0x45,0xc6,0x91,0x16,0x9b,0xcd,0x9c,0xba,0xc0,0xcb };
    const uint8_t PLAINTEXT[] = { 0x0f };
    const uint8_t CIPHERTEXT[] = { 0xff };
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

TEST_CASE("CFB8MCT256-DECRYPT-20", "[CFB8][MCT][256][DECRYPT][n20]") {
    const uint8_t KEY[] = { 0xd4,0x11,0x6e,0xed,0x30,0x5d,0xc7,0x65,0x76,0xf4,0xe1,0xcf,0x33,0x00,0xd7,0xc3,0x78,0xe0,0x68,0xe6,0xe7,0xaa,0x6d,0x81,0x5a,0xd8,0x76,0x1c,0xcc,0x1e,0x67,0xe8 };
    const uint8_t IV[] = { 0xa9,0x77,0x0c,0xd5,0x85,0xc8,0x04,0xb3,0xf6,0x4d,0x51,0xb4,0x22,0xd1,0xcc,0x0f };
    const uint8_t PLAINTEXT[] = { 0x28 };
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

TEST_CASE("CFB8MCT256-DECRYPT-21", "[CFB8][MCT][256][DECRYPT][n21]") {
    const uint8_t KEY[] = { 0x3a,0x06,0x91,0x1d,0x40,0x63,0x2d,0x17,0x2f,0xe8,0x63,0x98,0x28,0x56,0x1c,0x8f,0x09,0x4e,0x2f,0x0b,0xcc,0xca,0xdf,0xc0,0xc4,0x12,0x18,0x45,0xb9,0x28,0xcb,0xc0 };
    const uint8_t IV[] = { 0x71,0xae,0x47,0xed,0x2b,0x60,0xb2,0x41,0x9e,0xca,0x6e,0x59,0x75,0x36,0xac,0x28 };
    const uint8_t PLAINTEXT[] = { 0xc3 };
    const uint8_t CIPHERTEXT[] = { 0x4c };
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

TEST_CASE("CFB8MCT256-DECRYPT-22", "[CFB8][MCT][256][DECRYPT][n22]") {
    const uint8_t KEY[] = { 0x2e,0xf1,0x50,0x73,0x83,0x25,0xcd,0x1c,0xba,0xff,0x3f,0x9e,0x14,0x60,0x7b,0x5f,0x74,0xef,0x16,0xee,0x01,0xf5,0x38,0x20,0x5e,0x9e,0x17,0x59,0xf7,0x58,0xf4,0x03 };
    const uint8_t IV[] = { 0x7d,0xa1,0x39,0xe5,0xcd,0x3f,0xe7,0xe0,0x9a,0x8c,0x0f,0x1c,0x4e,0x70,0x3f,0xc3 };
    const uint8_t PLAINTEXT[] = { 0x8e };
    const uint8_t CIPHERTEXT[] = { 0xd0 };
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

TEST_CASE("CFB8MCT256-DECRYPT-23", "[CFB8][MCT][256][DECRYPT][n23]") {
    const uint8_t KEY[] = { 0x7e,0x37,0xb7,0xe8,0x3f,0x1c,0x67,0xbd,0xfc,0x06,0x78,0x51,0x51,0x81,0x4a,0x6e,0x60,0xc0,0xc2,0x28,0xe2,0x4f,0x19,0x71,0x24,0x45,0x3b,0x78,0x7e,0x4a,0x26,0x8d };
    const uint8_t IV[] = { 0x14,0x2f,0xd4,0xc6,0xe3,0xba,0x21,0x51,0x7a,0xdb,0x2c,0x21,0x89,0x12,0xd2,0x8e };
    const uint8_t PLAINTEXT[] = { 0xb8 };
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

TEST_CASE("CFB8MCT256-DECRYPT-24", "[CFB8][MCT][256][DECRYPT][n24]") {
    const uint8_t KEY[] = { 0x1d,0x1f,0x3c,0x0b,0x8a,0x5a,0x27,0xd5,0x6f,0xa0,0xd4,0xb9,0x43,0x71,0xbc,0xa5,0x3f,0x24,0xf0,0x15,0x21,0x9d,0x8a,0xbc,0x0c,0xe3,0x2b,0x05,0x05,0xaf,0xfa,0x35 };
    const uint8_t IV[] = { 0x5f,0xe4,0x32,0x3d,0xc3,0xd2,0x93,0xcd,0x28,0xa6,0x10,0x7d,0x7b,0xe5,0xdc,0xb8 };
    const uint8_t PLAINTEXT[] = { 0x04 };
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

TEST_CASE("CFB8MCT256-DECRYPT-25", "[CFB8][MCT][256][DECRYPT][n25]") {
    const uint8_t KEY[] = { 0x01,0xaf,0xf7,0xb5,0x2c,0x31,0xd6,0x71,0x47,0x3d,0x70,0x30,0x3a,0xc3,0xbc,0xab,0xba,0x6d,0x3c,0x5b,0xa9,0x5a,0x7a,0x3b,0xe0,0x92,0x9c,0xe4,0x17,0x53,0xf7,0x31 };
    const uint8_t IV[] = { 0x85,0x49,0xcc,0x4e,0x88,0xc7,0xf0,0x87,0xec,0x71,0xb7,0xe1,0x12,0xfc,0x0d,0x04 };
    const uint8_t PLAINTEXT[] = { 0x1d };
    const uint8_t CIPHERTEXT[] = { 0x0e };
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

TEST_CASE("CFB8MCT256-DECRYPT-26", "[CFB8][MCT][256][DECRYPT][n26]") {
    const uint8_t KEY[] = { 0xea,0x22,0x0f,0x45,0xe2,0x8e,0xd5,0xfd,0x22,0x3a,0x47,0x3b,0xa1,0xa5,0x53,0x3c,0x23,0x6c,0xb7,0x08,0x77,0x66,0xc8,0x2f,0xe2,0x87,0x9d,0x68,0xca,0xf7,0xf9,0x2c };
    const uint8_t IV[] = { 0x99,0x01,0x8b,0x53,0xde,0x3c,0xb2,0x14,0x02,0x15,0x01,0x8c,0xdd,0xa4,0x0e,0x1d };
    const uint8_t PLAINTEXT[] = { 0xe5 };
    const uint8_t CIPHERTEXT[] = { 0x97 };
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

TEST_CASE("CFB8MCT256-DECRYPT-27", "[CFB8][MCT][256][DECRYPT][n27]") {
    const uint8_t KEY[] = { 0xee,0x92,0x5b,0x13,0x00,0xc6,0xb8,0x11,0x84,0x27,0xc3,0xc3,0x5b,0x21,0xdd,0x66,0x4e,0x8a,0xae,0x01,0xf8,0x8a,0xb9,0x8a,0xc1,0x94,0x02,0x19,0x56,0x85,0xcd,0xc9 };
    const uint8_t IV[] = { 0x6d,0xe6,0x19,0x09,0x8f,0xec,0x71,0xa5,0x23,0x13,0x9f,0x71,0x9c,0x72,0x34,0xe5 };
    const uint8_t PLAINTEXT[] = { 0x5d };
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

TEST_CASE("CFB8MCT256-DECRYPT-28", "[CFB8][MCT][256][DECRYPT][n28]") {
    const uint8_t KEY[] = { 0x99,0xc6,0x9c,0x04,0xad,0x99,0xa2,0x93,0x26,0x38,0xd0,0x04,0x49,0xcf,0xb4,0x2f,0xa2,0xa6,0x77,0xdd,0xaf,0x2c,0x6d,0x83,0x73,0x83,0x7b,0x6d,0xa3,0xe6,0x78,0x94 };
    const uint8_t IV[] = { 0xec,0x2c,0xd9,0xdc,0x57,0xa6,0xd4,0x09,0xb2,0x17,0x79,0x74,0xf5,0x63,0xb5,0x5d };
    const uint8_t PLAINTEXT[] = { 0xe1 };
    const uint8_t CIPHERTEXT[] = { 0x49 };
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

TEST_CASE("CFB8MCT256-DECRYPT-29", "[CFB8][MCT][256][DECRYPT][n29]") {
    const uint8_t KEY[] = { 0xfd,0x9e,0x27,0xd8,0xf7,0x57,0xf0,0xee,0x11,0x88,0x5f,0xb0,0xc6,0xf5,0x03,0x8a,0xcb,0xcd,0x48,0xbc,0xe2,0x46,0x1b,0x34,0x29,0x73,0x4a,0x63,0x7a,0x85,0x48,0x75 };
    const uint8_t IV[] = { 0x69,0x6b,0x3f,0x61,0x4d,0x6a,0x76,0xb7,0x5a,0xf0,0x31,0x0e,0xd9,0x63,0x30,0xe1 };
    const uint8_t PLAINTEXT[] = { 0xb8 };
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

TEST_CASE("CFB8MCT256-DECRYPT-30", "[CFB8][MCT][256][DECRYPT][n30]") {
    const uint8_t KEY[] = { 0x85,0xc6,0x5f,0x0c,0x19,0xb1,0xbf,0xe8,0xf3,0xcb,0x7e,0x62,0x74,0x85,0xd5,0xed,0xc1,0x21,0xbd,0x47,0xe9,0x40,0x56,0x10,0xf7,0x87,0xa6,0x54,0x00,0xa6,0x37,0xcd };
    const uint8_t IV[] = { 0x0a,0xec,0xf5,0xfb,0x0b,0x06,0x4d,0x24,0xde,0xf4,0xec,0x37,0x7a,0x23,0x7f,0xb8 };
    const uint8_t PLAINTEXT[] = { 0x75 };
    const uint8_t CIPHERTEXT[] = { 0x67 };
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

TEST_CASE("CFB8MCT256-DECRYPT-31", "[CFB8][MCT][256][DECRYPT][n31]") {
    const uint8_t KEY[] = { 0x85,0x0f,0x24,0xab,0xe2,0xe1,0x95,0x0c,0x04,0x54,0x64,0xdf,0xda,0x9c,0x63,0x05,0x7c,0x43,0x6a,0x90,0x31,0x13,0xae,0x42,0x73,0x96,0x1f,0x07,0xe2,0x01,0x1a,0xb8 };
    const uint8_t IV[] = { 0xbd,0x62,0xd7,0xd7,0xd8,0x53,0xf8,0x52,0x84,0x11,0xb9,0x53,0xe2,0xa7,0x2d,0x75 };
    const uint8_t PLAINTEXT[] = { 0x50 };
    const uint8_t CIPHERTEXT[] = { 0xe8 };
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

TEST_CASE("CFB8MCT256-DECRYPT-32", "[CFB8][MCT][256][DECRYPT][n32]") {
    const uint8_t KEY[] = { 0x13,0x19,0x8a,0x05,0x3e,0xab,0xd7,0xaa,0x8b,0x78,0x15,0xe2,0xbb,0xbf,0x68,0x75,0xf8,0x89,0xcb,0xd2,0xf2,0xfe,0x7c,0xb6,0xa4,0xa6,0x4a,0xd0,0x38,0x90,0xe9,0xe8 };
    const uint8_t IV[] = { 0x84,0xca,0xa1,0x42,0xc3,0xed,0xd2,0xf4,0xd7,0x30,0x55,0xd7,0xda,0x91,0xf3,0x50 };
    const uint8_t PLAINTEXT[] = { 0x6a };
    const uint8_t CIPHERTEXT[] = { 0x70 };
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

TEST_CASE("CFB8MCT256-DECRYPT-33", "[CFB8][MCT][256][DECRYPT][n33]") {
    const uint8_t KEY[] = { 0xfd,0x7e,0x46,0x65,0xa9,0xfe,0x67,0xe1,0x13,0x20,0xb0,0x41,0x51,0x1b,0x62,0x17,0xec,0x81,0xb2,0xaf,0xaa,0xcf,0xbf,0x1d,0x72,0x50,0x1e,0x79,0x2d,0x7b,0xf7,0x82 };
    const uint8_t IV[] = { 0x14,0x08,0x79,0x7d,0x58,0x31,0xc3,0xab,0xd6,0xf6,0x54,0xa9,0x15,0xeb,0x1e,0x6a };
    const uint8_t PLAINTEXT[] = { 0x0e };
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

TEST_CASE("CFB8MCT256-DECRYPT-34", "[CFB8][MCT][256][DECRYPT][n34]") {
    const uint8_t KEY[] = { 0x7f,0xd7,0xf2,0x2a,0x14,0x92,0x26,0xd3,0xe8,0xe0,0xd7,0x03,0xa7,0xda,0x98,0xae,0xe2,0x67,0x22,0xc4,0x15,0xf5,0xe0,0x05,0x9c,0x89,0xcc,0x31,0xf8,0xd9,0x6a,0x8c };
    const uint8_t IV[] = { 0x0e,0xe6,0x90,0x6b,0xbf,0x3a,0x5f,0x18,0xee,0xd9,0xd2,0x48,0xd5,0xa2,0x9d,0x0e };
    const uint8_t PLAINTEXT[] = { 0xa8 };
    const uint8_t CIPHERTEXT[] = { 0xb9 };
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

TEST_CASE("CFB8MCT256-DECRYPT-35", "[CFB8][MCT][256][DECRYPT][n35]") {
    const uint8_t KEY[] = { 0x00,0x10,0x94,0x5c,0x67,0xc6,0x5f,0x18,0x99,0x53,0xf4,0xd2,0x91,0x77,0xe6,0x60,0x8e,0x0b,0xd9,0x72,0x4c,0xe4,0x66,0x19,0xc4,0xf2,0x40,0x7b,0x5b,0x02,0x18,0x24 };
    const uint8_t IV[] = { 0x6c,0x6c,0xfb,0xb6,0x59,0x11,0x86,0x1c,0x58,0x7b,0x8c,0x4a,0xa3,0xdb,0x72,0xa8 };
    const uint8_t PLAINTEXT[] = { 0x5d };
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

TEST_CASE("CFB8MCT256-DECRYPT-36", "[CFB8][MCT][256][DECRYPT][n36]") {
    const uint8_t KEY[] = { 0x82,0xff,0xd4,0x31,0x07,0xd1,0x58,0x7c,0x18,0x4f,0x95,0x74,0xcf,0xdc,0x38,0xa0,0x99,0x61,0xc6,0x71,0xa6,0x84,0xff,0x1a,0x43,0x45,0xba,0xaa,0x52,0x73,0x18,0x79 };
    const uint8_t IV[] = { 0x17,0x6a,0x1f,0x03,0xea,0x60,0x99,0x03,0x87,0xb7,0xfa,0xd1,0x09,0x71,0x00,0x5d };
    const uint8_t PLAINTEXT[] = { 0x3d };
    const uint8_t CIPHERTEXT[] = { 0xc0 };
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

TEST_CASE("CFB8MCT256-DECRYPT-37", "[CFB8][MCT][256][DECRYPT][n37]") {
    const uint8_t KEY[] = { 0x54,0x88,0x1b,0xeb,0xd2,0xa8,0xf1,0xb8,0x41,0x6b,0x31,0xee,0x65,0x85,0xa8,0x25,0x0d,0x3a,0xee,0x9d,0xb6,0x1b,0xac,0xe4,0xa2,0xe4,0x4c,0xb9,0x8c,0x22,0x8a,0x44 };
    const uint8_t IV[] = { 0x94,0x5b,0x28,0xec,0x10,0x9f,0x53,0xfe,0xe1,0xa1,0xf6,0x13,0xde,0x51,0x92,0x3d };
    const uint8_t PLAINTEXT[] = { 0x00 };
    const uint8_t CIPHERTEXT[] = { 0x85 };
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

TEST_CASE("CFB8MCT256-DECRYPT-38", "[CFB8][MCT][256][DECRYPT][n38]") {
    const uint8_t KEY[] = { 0xc0,0xd1,0x75,0x6c,0xb4,0xd8,0x48,0x22,0x12,0x5a,0x53,0xc0,0x44,0xc5,0xfd,0x5e,0x2b,0xd4,0xed,0x81,0xe8,0xc8,0xaa,0x73,0xd4,0x9d,0x6e,0xe0,0x3d,0xae,0xbb,0x44 };
    const uint8_t IV[] = { 0x26,0xee,0x03,0x1c,0x5e,0xd3,0x06,0x97,0x76,0x79,0x22,0x59,0xb1,0x8c,0x31,0x00 };
    const uint8_t PLAINTEXT[] = { 0x25 };
    const uint8_t CIPHERTEXT[] = { 0x7b };
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

TEST_CASE("CFB8MCT256-DECRYPT-39", "[CFB8][MCT][256][DECRYPT][n39]") {
    const uint8_t KEY[] = { 0x06,0xbb,0x2a,0x01,0xef,0x11,0xb3,0x09,0x34,0x80,0x6d,0x1c,0x3e,0x58,0x3d,0xf6,0xdd,0x01,0xca,0xd7,0x10,0x2a,0xbc,0x10,0xf2,0x87,0x5c,0xac,0xcb,0xff,0x0d,0x61 };
    const uint8_t IV[] = { 0xf6,0xd5,0x27,0x56,0xf8,0xe2,0x16,0x63,0x26,0x1a,0x32,0x4c,0xf6,0x51,0xb6,0x25 };
    const uint8_t PLAINTEXT[] = { 0xfb };
    const uint8_t CIPHERTEXT[] = { 0xa8 };
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

TEST_CASE("CFB8MCT256-DECRYPT-40", "[CFB8][MCT][256][DECRYPT][n40]") {
    const uint8_t KEY[] = { 0x9f,0x14,0x40,0x2b,0x3b,0xc8,0x5e,0x04,0x60,0xdb,0x36,0x93,0xc9,0xe9,0x8c,0x3a,0x11,0xe4,0xeb,0x29,0xb7,0x28,0xd9,0xc6,0x3d,0xff,0xd9,0x5b,0xbf,0xfc,0x6c,0x9a };
    const uint8_t IV[] = { 0xcc,0xe5,0x21,0xfe,0xa7,0x02,0x65,0xd6,0xcf,0x78,0x85,0xf7,0x74,0x03,0x61,0xfb };
    const uint8_t PLAINTEXT[] = { 0x2d };
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

TEST_CASE("CFB8MCT256-DECRYPT-41", "[CFB8][MCT][256][DECRYPT][n41]") {
    const uint8_t KEY[] = { 0xd0,0x32,0x11,0xe0,0xcb,0x6a,0xf7,0x9c,0xbb,0xbe,0x74,0x7e,0x9b,0xa2,0xb5,0xba,0xb4,0x06,0x43,0xd0,0xa1,0x7a,0xa5,0x22,0x09,0xb4,0xac,0xa3,0x93,0x2b,0x74,0xb7 };
    const uint8_t IV[] = { 0xa5,0xe2,0xa8,0xf9,0x16,0x52,0x7c,0xe4,0x34,0x4b,0x75,0xf8,0x2c,0xd7,0x18,0x2d };
    const uint8_t PLAINTEXT[] = { 0x78 };
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

TEST_CASE("CFB8MCT256-DECRYPT-42", "[CFB8][MCT][256][DECRYPT][n42]") {
    const uint8_t KEY[] = { 0x95,0x58,0x26,0x1f,0x75,0x04,0x83,0x76,0x83,0x83,0xa7,0x7d,0x37,0x49,0x41,0xf7,0x51,0x44,0x62,0x83,0x60,0x1f,0x6e,0x6e,0xf7,0xe8,0x1e,0x06,0xad,0x08,0x6f,0xcf };
    const uint8_t IV[] = { 0xe5,0x42,0x21,0x53,0xc1,0x65,0xcb,0x4c,0xfe,0x5c,0xb2,0xa5,0x3e,0x23,0x1b,0x78 };
    const uint8_t PLAINTEXT[] = { 0x5f };
    const uint8_t CIPHERTEXT[] = { 0x4d };
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

TEST_CASE("CFB8MCT256-DECRYPT-43", "[CFB8][MCT][256][DECRYPT][n43]") {
    const uint8_t KEY[] = { 0x56,0x7e,0x37,0x28,0xd8,0x7d,0xa0,0x50,0x9d,0x31,0x4c,0xdc,0x06,0x69,0x01,0x26,0x5b,0x63,0x1a,0xba,0x59,0xf3,0x7c,0x13,0x94,0x8b,0xe9,0xa3,0xc1,0xb4,0x1e,0x90 };
    const uint8_t IV[] = { 0x0a,0x27,0x78,0x39,0x39,0xec,0x12,0x7d,0x63,0x63,0xf7,0xa5,0x6c,0xbc,0x71,0x5f };
    const uint8_t PLAINTEXT[] = { 0x1b };
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

TEST_CASE("CFB8MCT256-DECRYPT-44", "[CFB8][MCT][256][DECRYPT][n44]") {
    const uint8_t KEY[] = { 0xf8,0xc2,0x08,0x2b,0xe6,0xcf,0x2e,0x56,0x1f,0x32,0xc1,0xe0,0x31,0xbc,0x6c,0xb7,0x67,0xf4,0x2c,0x3d,0xec,0xcf,0x98,0x16,0x1b,0xa8,0x61,0xd2,0x24,0x29,0x84,0x8b };
    const uint8_t IV[] = { 0x3c,0x97,0x36,0x87,0xb5,0x3c,0xe4,0x05,0x8f,0x23,0x88,0x71,0xe5,0x9d,0x9a,0x1b };
    const uint8_t PLAINTEXT[] = { 0xb2 };
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

TEST_CASE("CFB8MCT256-DECRYPT-45", "[CFB8][MCT][256][DECRYPT][n45]") {
    const uint8_t KEY[] = { 0x12,0xfb,0x00,0xce,0xc4,0x91,0xe2,0x64,0x32,0x7e,0x37,0xaf,0x7a,0xe7,0xfe,0x8f,0x82,0x1a,0x84,0x0c,0x32,0x8f,0x12,0x4d,0x5b,0xef,0x20,0x15,0xcc,0x33,0x16,0x39 };
    const uint8_t IV[] = { 0xe5,0xee,0xa8,0x31,0xde,0x40,0x8a,0x5b,0x40,0x47,0x41,0xc7,0xe8,0x1a,0x92,0xb2 };
    const uint8_t PLAINTEXT[] = { 0x9d };
    const uint8_t CIPHERTEXT[] = { 0x38 };
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

TEST_CASE("CFB8MCT256-DECRYPT-46", "[CFB8][MCT][256][DECRYPT][n46]") {
    const uint8_t KEY[] = { 0xd2,0x02,0x86,0x15,0xb3,0x5a,0xb2,0xcd,0x50,0x1c,0xaf,0xcc,0xef,0x4f,0xd3,0x24,0x7d,0x9e,0xbc,0xa0,0xfa,0x8c,0xcc,0x4c,0xf2,0x55,0x14,0xce,0xa6,0xe1,0x4b,0xa4 };
    const uint8_t IV[] = { 0xff,0x84,0x38,0xac,0xc8,0x03,0xde,0x01,0xa9,0xba,0x34,0xdb,0x6a,0xd2,0x5d,0x9d };
    const uint8_t PLAINTEXT[] = { 0x34 };
    const uint8_t CIPHERTEXT[] = { 0xab };
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

TEST_CASE("CFB8MCT256-DECRYPT-47", "[CFB8][MCT][256][DECRYPT][n47]") {
    const uint8_t KEY[] = { 0x56,0xd8,0x33,0x81,0x54,0xbb,0xea,0x01,0x71,0x37,0x65,0x0e,0xa1,0xb4,0xe3,0xcf,0x9d,0x66,0x56,0xce,0x30,0xad,0x6b,0x25,0x28,0xfc,0xf1,0x8b,0x4c,0x24,0xe1,0x90 };
    const uint8_t IV[] = { 0xe0,0xf8,0xea,0x6e,0xca,0x21,0xa7,0x69,0xda,0xa9,0xe5,0x45,0xea,0xc5,0xaa,0x34 };
    const uint8_t PLAINTEXT[] = { 0xa8 };
    const uint8_t CIPHERTEXT[] = { 0xeb };
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

TEST_CASE("CFB8MCT256-DECRYPT-48", "[CFB8][MCT][256][DECRYPT][n48]") {
    const uint8_t KEY[] = { 0x43,0x5e,0x90,0xaa,0xfb,0xde,0x6a,0x6b,0x71,0xe3,0xae,0xb0,0x94,0x3e,0x79,0x45,0xcb,0x9c,0x1e,0x5a,0x02,0x12,0xf6,0x46,0xb9,0xd2,0xad,0xbb,0xc0,0x57,0xf1,0x38 };
    const uint8_t IV[] = { 0x56,0xfa,0x48,0x94,0x32,0xbf,0x9d,0x63,0x91,0x2e,0x5c,0x30,0x8c,0x73,0x10,0xa8 };
    const uint8_t PLAINTEXT[] = { 0xff };
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

TEST_CASE("CFB8MCT256-DECRYPT-49", "[CFB8][MCT][256][DECRYPT][n49]") {
    const uint8_t KEY[] = { 0x70,0x4d,0x67,0x60,0x6a,0x05,0x50,0x1f,0x6c,0xe4,0x1f,0xb0,0xab,0x5a,0x5d,0x07,0x5c,0x19,0x8d,0x70,0x83,0xd9,0xcd,0x8e,0xdc,0x74,0xe8,0xc1,0x57,0xa1,0x01,0xc7 };
    const uint8_t IV[] = { 0x97,0x85,0x93,0x2a,0x81,0xcb,0x3b,0xc8,0x65,0xa6,0x45,0x7a,0x97,0xf6,0xf0,0xff };
    const uint8_t PLAINTEXT[] = { 0x3d };
    const uint8_t CIPHERTEXT[] = { 0x42 };
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

TEST_CASE("CFB8MCT256-DECRYPT-50", "[CFB8][MCT][256][DECRYPT][n50]") {
    const uint8_t KEY[] = { 0x88,0xa9,0xa7,0xea,0x1b,0x3c,0x08,0x31,0x45,0xb1,0xca,0x1b,0x9c,0xd3,0x53,0xaa,0x3f,0x0a,0x81,0xe5,0xdf,0x9e,0x4f,0x0f,0xf8,0x7a,0x8f,0x45,0xcb,0x7c,0xbf,0xfa };
    const uint8_t IV[] = { 0x63,0x13,0x0c,0x95,0x5c,0x47,0x82,0x81,0x24,0x0e,0x67,0x84,0x9c,0xdd,0xbe,0x3d };
    const uint8_t PLAINTEXT[] = { 0x79 };
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

TEST_CASE("CFB8MCT256-DECRYPT-51", "[CFB8][MCT][256][DECRYPT][n51]") {
    const uint8_t KEY[] = { 0x3d,0x86,0x25,0xb3,0x40,0x6c,0xc5,0xfb,0x25,0xac,0xec,0xb9,0x50,0xfa,0xbe,0x5d,0x3c,0xdf,0x1c,0xae,0xe6,0xcb,0x95,0x86,0x3f,0x59,0xf6,0xce,0x05,0x8a,0x75,0x83 };
    const uint8_t IV[] = { 0x03,0xd5,0x9d,0x4b,0x39,0x55,0xda,0x89,0xc7,0x23,0x79,0x8b,0xce,0xf6,0xca,0x79 };
    const uint8_t PLAINTEXT[] = { 0x0c };
    const uint8_t CIPHERTEXT[] = { 0xf7 };
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

TEST_CASE("CFB8MCT256-DECRYPT-52", "[CFB8][MCT][256][DECRYPT][n52]") {
    const uint8_t KEY[] = { 0x61,0x71,0xe9,0x5e,0xb6,0x6e,0x64,0x98,0x60,0x87,0xe0,0xbb,0x69,0x44,0x04,0x2e,0x86,0xee,0x77,0x01,0x55,0xc7,0x6b,0x38,0x09,0xcb,0xeb,0xbe,0x26,0x8e,0x30,0x8f };
    const uint8_t IV[] = { 0xba,0x31,0x6b,0xaf,0xb3,0x0c,0xfe,0xbe,0x36,0x92,0x1d,0x70,0x23,0x04,0x45,0x0c };
    const uint8_t PLAINTEXT[] = { 0x8f };
    const uint8_t CIPHERTEXT[] = { 0x73 };
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

TEST_CASE("CFB8MCT256-DECRYPT-53", "[CFB8][MCT][256][DECRYPT][n53]") {
    const uint8_t KEY[] = { 0x17,0xd2,0x4a,0xfc,0x39,0xca,0x16,0xc5,0xb6,0x5e,0x9d,0xde,0xbb,0xea,0x71,0xaa,0x4c,0xc1,0x33,0xe1,0xda,0xec,0xb8,0xcf,0x3a,0xfa,0x58,0x67,0xbd,0xd8,0x10,0x00 };
    const uint8_t IV[] = { 0xca,0x2f,0x44,0xe0,0x8f,0x2b,0xd3,0xf7,0x33,0x31,0xb3,0xd9,0x9b,0x56,0x20,0x8f };
    const uint8_t PLAINTEXT[] = { 0x63 };
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

TEST_CASE("CFB8MCT256-DECRYPT-54", "[CFB8][MCT][256][DECRYPT][n54]") {
    const uint8_t KEY[] = { 0x3d,0x9c,0x0c,0xc7,0xf9,0xaf,0x00,0xd1,0x4b,0x0b,0xac,0x30,0x7c,0xca,0xb3,0x4e,0x3a,0xb9,0xee,0x27,0x40,0x07,0x60,0x30,0x72,0xbc,0x01,0x47,0x66,0x38,0x4f,0x63 };
    const uint8_t IV[] = { 0x76,0x78,0xdd,0xc6,0x9a,0xeb,0xd8,0xff,0x48,0x46,0x59,0x20,0xdb,0xe0,0x5f,0x63 };
    const uint8_t PLAINTEXT[] = { 0x69 };
    const uint8_t CIPHERTEXT[] = { 0xe4 };
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

TEST_CASE("CFB8MCT256-DECRYPT-55", "[CFB8][MCT][256][DECRYPT][n55]") {
    const uint8_t KEY[] = { 0x4e,0xa6,0x00,0xc9,0xa2,0xeb,0xa0,0x8c,0x99,0xa2,0xb7,0xd0,0x85,0xf4,0x67,0x6b,0x80,0xdc,0x3d,0x55,0xc4,0x67,0x55,0x03,0xa6,0x2f,0x65,0x70,0x16,0x07,0x74,0x0a };
    const uint8_t IV[] = { 0xba,0x65,0xd3,0x72,0x84,0x60,0x35,0x33,0xd4,0x93,0x64,0x37,0x70,0x3f,0x3b,0x69 };
    const uint8_t PLAINTEXT[] = { 0x2c };
    const uint8_t CIPHERTEXT[] = { 0x25 };
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

TEST_CASE("CFB8MCT256-DECRYPT-56", "[CFB8][MCT][256][DECRYPT][n56]") {
    const uint8_t KEY[] = { 0xf4,0xc6,0x6d,0x91,0x6d,0x2c,0x2c,0x6d,0x09,0xd9,0x0b,0x7b,0x3f,0x18,0xd3,0x44,0xf8,0xd7,0xba,0x90,0x54,0x0b,0x37,0x28,0x74,0xcd,0xfe,0xde,0x69,0xc7,0x69,0x26 };
    const uint8_t IV[] = { 0x78,0x0b,0x87,0xc5,0x90,0x6c,0x62,0x2b,0xd2,0xe2,0x9b,0xae,0x7f,0xc0,0x1d,0x2c };
    const uint8_t PLAINTEXT[] = { 0x70 };
    const uint8_t CIPHERTEXT[] = { 0x2f };
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

TEST_CASE("CFB8MCT256-DECRYPT-57", "[CFB8][MCT][256][DECRYPT][n57]") {
    const uint8_t KEY[] = { 0xad,0x35,0x15,0x89,0x3b,0x82,0xd9,0x61,0xef,0x09,0x66,0xad,0xbc,0x6b,0xd6,0x29,0x49,0x55,0x11,0x11,0xac,0x7a,0x3e,0x04,0x07,0xea,0xab,0xc8,0x5c,0xa1,0xc8,0x56 };
    const uint8_t IV[] = { 0xb1,0x82,0xab,0x81,0xf8,0x71,0x09,0x2c,0x73,0x27,0x55,0x16,0x35,0x66,0xa1,0x70 };
    const uint8_t PLAINTEXT[] = { 0x97 };
    const uint8_t CIPHERTEXT[] = { 0x6d };
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

TEST_CASE("CFB8MCT256-DECRYPT-58", "[CFB8][MCT][256][DECRYPT][n58]") {
    const uint8_t KEY[] = { 0xbc,0xf1,0x75,0x51,0x6a,0xef,0xed,0xe8,0xc8,0xa3,0x4c,0xb8,0xfd,0x8b,0xcd,0x22,0x6e,0x16,0xfc,0x3b,0x18,0x86,0x4e,0xaa,0x3e,0x19,0x62,0x97,0x1c,0x62,0x23,0xc1 };
    const uint8_t IV[] = { 0x27,0x43,0xed,0x2a,0xb4,0xfc,0x70,0xae,0x39,0xf3,0xc9,0x5f,0x40,0xc3,0xeb,0x97 };
    const uint8_t PLAINTEXT[] = { 0xca };
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

TEST_CASE("CFB8MCT256-DECRYPT-59", "[CFB8][MCT][256][DECRYPT][n59]") {
    const uint8_t KEY[] = { 0x14,0xcb,0x7c,0x9f,0x50,0x4c,0x08,0x44,0x08,0x2c,0xc0,0x26,0xc9,0x27,0xfe,0x81,0x30,0x18,0x09,0xce,0x8b,0x95,0x77,0x8e,0xa4,0x9b,0x92,0x59,0x19,0xb1,0xcb,0x0b };
    const uint8_t IV[] = { 0x5e,0x0e,0xf5,0xf5,0x93,0x13,0x39,0x24,0x9a,0x82,0xf0,0xce,0x05,0xd3,0xe8,0xca };
    const uint8_t PLAINTEXT[] = { 0xd2 };
    const uint8_t CIPHERTEXT[] = { 0xa3 };
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

TEST_CASE("CFB8MCT256-DECRYPT-60", "[CFB8][MCT][256][DECRYPT][n60]") {
    const uint8_t KEY[] = { 0xdd,0x4e,0x12,0x24,0x8c,0xe5,0xf8,0x06,0x3a,0xd3,0xa3,0x78,0x96,0x0e,0xda,0xed,0x42,0xe6,0xcf,0x0b,0x93,0xcb,0x6c,0x9a,0xc0,0x85,0x0d,0xf1,0xcc,0xc3,0xb1,0xd9 };
    const uint8_t IV[] = { 0x72,0xfe,0xc6,0xc5,0x18,0x5e,0x1b,0x14,0x64,0x1e,0x9f,0xa8,0xd5,0x72,0x7a,0xd2 };
    const uint8_t PLAINTEXT[] = { 0x9b };
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

TEST_CASE("CFB8MCT256-DECRYPT-61", "[CFB8][MCT][256][DECRYPT][n61]") {
    const uint8_t KEY[] = { 0xd3,0xf9,0xf8,0xd0,0x0e,0x40,0xd0,0xd2,0xb1,0x9c,0xb4,0xb8,0xc0,0xd8,0xe3,0x2d,0xdd,0x9e,0xe5,0x95,0x38,0x6b,0xf6,0xcf,0xcf,0x3b,0x77,0x6f,0xa6,0x1b,0x39,0x42 };
    const uint8_t IV[] = { 0x9f,0x78,0x2a,0x9e,0xab,0xa0,0x9a,0x55,0x0f,0xbe,0x7a,0x9e,0x6a,0xd8,0x88,0x9b };
    const uint8_t PLAINTEXT[] = { 0x59 };
    const uint8_t CIPHERTEXT[] = { 0xc0 };
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

TEST_CASE("CFB8MCT256-DECRYPT-62", "[CFB8][MCT][256][DECRYPT][n62]") {
    const uint8_t KEY[] = { 0x7e,0x61,0xbf,0xee,0x9d,0x24,0x1d,0x1e,0xf3,0x8e,0x24,0x60,0xe3,0xf3,0xc6,0x96,0xc6,0x17,0x97,0x92,0xc5,0xf8,0xfa,0x97,0x46,0xf8,0xbf,0x2c,0x8a,0x69,0x38,0x1b };
    const uint8_t IV[] = { 0x1b,0x89,0x72,0x07,0xfd,0x93,0x0c,0x58,0x89,0xc3,0xc8,0x43,0x2c,0x72,0x01,0x59 };
    const uint8_t PLAINTEXT[] = { 0x26 };
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

TEST_CASE("CFB8MCT256-DECRYPT-63", "[CFB8][MCT][256][DECRYPT][n63]") {
    const uint8_t KEY[] = { 0x7a,0x83,0x72,0x45,0x8a,0xfb,0xd8,0x40,0x77,0x3a,0xce,0xda,0xa3,0x0f,0x3e,0x2c,0x7d,0x1b,0x9d,0x09,0x27,0x80,0xa2,0x05,0x7d,0xe3,0x50,0x9d,0x4d,0x2d,0xc2,0x3d };
    const uint8_t IV[] = { 0xbb,0x0c,0x0a,0x9b,0xe2,0x78,0x58,0x92,0x3b,0x1b,0xef,0xb1,0xc7,0x44,0xfa,0x26 };
    const uint8_t PLAINTEXT[] = { 0x89 };
    const uint8_t CIPHERTEXT[] = { 0xba };
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

TEST_CASE("CFB8MCT256-DECRYPT-64", "[CFB8][MCT][256][DECRYPT][n64]") {
    const uint8_t KEY[] = { 0xcd,0x63,0x69,0x06,0x14,0xc6,0x6d,0x27,0xe0,0x00,0x4c,0x5f,0x60,0x62,0x43,0x19,0x60,0x29,0xaa,0xc2,0xc3,0x45,0x56,0x80,0x22,0x4b,0xd1,0x21,0xe6,0x43,0x87,0xb4 };
    const uint8_t IV[] = { 0x1d,0x32,0x37,0xcb,0xe4,0xc5,0xf4,0x85,0x5f,0xa8,0x81,0xbc,0xab,0x6e,0x45,0x89 };
    const uint8_t PLAINTEXT[] = { 0xc4 };
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

TEST_CASE("CFB8MCT256-DECRYPT-65", "[CFB8][MCT][256][DECRYPT][n65]") {
    const uint8_t KEY[] = { 0x10,0x3e,0xf8,0x84,0x53,0xf3,0xe9,0x8e,0x8a,0xd1,0xad,0x62,0x72,0x6a,0xe7,0x7e,0x55,0x15,0x57,0x68,0xf2,0x87,0x21,0xb9,0x30,0x02,0x2c,0x22,0x29,0x3c,0xc0,0x70 };
    const uint8_t IV[] = { 0x35,0x3c,0xfd,0xaa,0x31,0xc2,0x77,0x39,0x12,0x49,0xfd,0x03,0xcf,0x7f,0x47,0xc4 };
    const uint8_t PLAINTEXT[] = { 0x70 };
    const uint8_t CIPHERTEXT[] = { 0x67 };
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

TEST_CASE("CFB8MCT256-DECRYPT-66", "[CFB8][MCT][256][DECRYPT][n66]") {
    const uint8_t KEY[] = { 0xf7,0x15,0x65,0x77,0xba,0xbe,0xe0,0x4a,0xf9,0xe4,0xca,0x9f,0xd1,0x2d,0x51,0x8e,0xc6,0xb4,0xd4,0x1c,0x65,0x58,0x62,0x16,0x3c,0x00,0x3f,0xf9,0x4a,0x16,0xf8,0x00 };
    const uint8_t IV[] = { 0x93,0xa1,0x83,0x74,0x97,0xdf,0x43,0xaf,0x0c,0x02,0x13,0xdb,0x63,0x2a,0x38,0x70 };
    const uint8_t PLAINTEXT[] = { 0x60 };
    const uint8_t CIPHERTEXT[] = { 0xf0 };
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

TEST_CASE("CFB8MCT256-DECRYPT-67", "[CFB8][MCT][256][DECRYPT][n67]") {
    const uint8_t KEY[] = { 0xe5,0x7d,0xd3,0x19,0xe3,0xc8,0x12,0xa3,0x6d,0x39,0xe4,0x55,0x70,0x93,0x31,0xb5,0x07,0x82,0xa9,0x70,0xcb,0x3d,0x47,0x5b,0x89,0x7e,0x1f,0x3b,0x95,0x8c,0xc9,0x60 };
    const uint8_t IV[] = { 0xc1,0x36,0x7d,0x6c,0xae,0x65,0x25,0x4d,0xb5,0x7e,0x20,0xc2,0xdf,0x9a,0x31,0x60 };
    const uint8_t PLAINTEXT[] = { 0x20 };
    const uint8_t CIPHERTEXT[] = { 0x3b };
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

TEST_CASE("CFB8MCT256-DECRYPT-68", "[CFB8][MCT][256][DECRYPT][n68]") {
    const uint8_t KEY[] = { 0x15,0xd8,0x59,0x8e,0xac,0x9d,0x2c,0x74,0xc3,0x6b,0x2d,0x43,0xbf,0x94,0x6a,0x8f,0x86,0x56,0x78,0x86,0x18,0x8a,0x5c,0xb9,0x9e,0x30,0x13,0xc4,0xc2,0x84,0x28,0x40 };
    const uint8_t IV[] = { 0x81,0xd4,0xd1,0xf6,0xd3,0xb7,0x1b,0xe2,0x17,0x4e,0x0c,0xff,0x57,0x08,0xe1,0x20 };
    const uint8_t PLAINTEXT[] = { 0xbe };
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

TEST_CASE("CFB8MCT256-DECRYPT-69", "[CFB8][MCT][256][DECRYPT][n69]") {
    const uint8_t KEY[] = { 0x95,0x89,0xcd,0x47,0x53,0x74,0xff,0x1c,0x72,0x11,0x4c,0x91,0xde,0x36,0x1b,0x1b,0xc9,0x88,0x00,0xfc,0x82,0x69,0x31,0x65,0xf5,0x25,0x80,0x64,0x4e,0x09,0x43,0xfe };
    const uint8_t IV[] = { 0x4f,0xde,0x78,0x7a,0x9a,0xe3,0x6d,0xdc,0x6b,0x15,0x93,0xa0,0x8c,0x8d,0x6b,0xbe };
    const uint8_t PLAINTEXT[] = { 0x72 };
    const uint8_t CIPHERTEXT[] = { 0x94 };
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

TEST_CASE("CFB8MCT256-DECRYPT-70", "[CFB8][MCT][256][DECRYPT][n70]") {
    const uint8_t KEY[] = { 0xaa,0xfc,0x26,0x5c,0x6c,0x96,0x2f,0xd7,0xb5,0x02,0x0b,0xde,0x16,0xa6,0xf0,0x14,0x33,0x6d,0xe3,0x63,0x12,0xb5,0x74,0x30,0x7a,0xeb,0xec,0xda,0x53,0xf1,0x46,0x8c };
    const uint8_t IV[] = { 0xfa,0xe5,0xe3,0x9f,0x90,0xdc,0x45,0x55,0x8f,0xce,0x6c,0xbe,0x1d,0xf8,0x05,0x72 };
    const uint8_t PLAINTEXT[] = { 0x71 };
    const uint8_t CIPHERTEXT[] = { 0x0f };
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

TEST_CASE("CFB8MCT256-DECRYPT-71", "[CFB8][MCT][256][DECRYPT][n71]") {
    const uint8_t KEY[] = { 0xba,0x55,0xd3,0x4f,0x53,0x38,0xf4,0x38,0x2f,0x7d,0x0f,0x57,0xe2,0xcb,0x50,0x76,0x4c,0xb9,0x3c,0x2a,0x5e,0x9e,0x12,0xba,0x03,0x97,0x89,0xf2,0x72,0xd7,0x06,0xfd };
    const uint8_t IV[] = { 0x7f,0xd4,0xdf,0x49,0x4c,0x2b,0x66,0x8a,0x79,0x7c,0x65,0x28,0x21,0x26,0x40,0x71 };
    const uint8_t PLAINTEXT[] = { 0x27 };
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

TEST_CASE("CFB8MCT256-DECRYPT-72", "[CFB8][MCT][256][DECRYPT][n72]") {
    const uint8_t KEY[] = { 0x10,0xa6,0x8b,0xd1,0xf4,0x02,0xde,0xe9,0x62,0x06,0x86,0xfa,0x13,0x66,0x01,0x57,0xdf,0x9e,0x7f,0xd4,0xe4,0x37,0xe9,0xa0,0x69,0xdd,0xda,0x7f,0xc9,0xcc,0x2d,0xda };
    const uint8_t IV[] = { 0x93,0x27,0x43,0xfe,0xba,0xa9,0xfb,0x1a,0x6a,0x4a,0x53,0x8d,0xbb,0x1b,0x2b,0x27 };
    const uint8_t PLAINTEXT[] = { 0x05 };
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

TEST_CASE("CFB8MCT256-DECRYPT-73", "[CFB8][MCT][256][DECRYPT][n73]") {
    const uint8_t KEY[] = { 0x29,0xd3,0xc2,0x36,0x9c,0xf1,0x60,0x15,0x7b,0x0a,0x30,0x7d,0xa1,0xdc,0xb2,0x59,0x94,0x07,0xce,0xe1,0x47,0xf1,0x5c,0x76,0xfa,0x63,0x48,0xf1,0x9d,0x86,0xd5,0xdf };
    const uint8_t IV[] = { 0x4b,0x99,0xb1,0x35,0xa3,0xc6,0xb5,0xd6,0x93,0xbe,0x92,0x8e,0x54,0x4a,0xf8,0x05 };
    const uint8_t PLAINTEXT[] = { 0xd2 };
    const uint8_t CIPHERTEXT[] = { 0x0e };
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

TEST_CASE("CFB8MCT256-DECRYPT-74", "[CFB8][MCT][256][DECRYPT][n74]") {
    const uint8_t KEY[] = { 0x67,0xce,0xbc,0x2b,0x99,0xb7,0x54,0x23,0x6a,0xaf,0x87,0x05,0x0f,0xad,0x3f,0xf5,0x46,0x7d,0xa3,0x99,0x61,0x24,0x07,0x99,0x32,0xbc,0x7c,0x4c,0x3a,0x93,0xbf,0x0d };
    const uint8_t IV[] = { 0xd2,0x7a,0x6d,0x78,0x26,0xd5,0x5b,0xef,0xc8,0xdf,0x34,0xbd,0xa7,0x15,0x6a,0xd2 };
    const uint8_t PLAINTEXT[] = { 0x12 };
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

TEST_CASE("CFB8MCT256-DECRYPT-75", "[CFB8][MCT][256][DECRYPT][n75]") {
    const uint8_t KEY[] = { 0x68,0x30,0xdf,0x02,0x38,0x8c,0xd1,0x32,0x10,0xaf,0xd0,0x75,0x50,0xc8,0x1a,0xed,0x72,0xfb,0xa1,0x2f,0xad,0xe8,0xb2,0x28,0x4c,0x45,0x81,0xf6,0x4a,0xa2,0x27,0x1f };
    const uint8_t IV[] = { 0x34,0x86,0x02,0xb6,0xcc,0xcc,0xb5,0xb1,0x7e,0xf9,0xfd,0xba,0x70,0x31,0x98,0x12 };
    const uint8_t PLAINTEXT[] = { 0x58 };
    const uint8_t CIPHERTEXT[] = { 0x18 };
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

TEST_CASE("CFB8MCT256-DECRYPT-76", "[CFB8][MCT][256][DECRYPT][n76]") {
    const uint8_t KEY[] = { 0x7c,0x63,0x2f,0xd0,0xc9,0xd6,0x18,0xe8,0x6c,0x68,0x47,0xcb,0x63,0x9e,0xc9,0xb4,0x8d,0x12,0x8d,0xc1,0xba,0x05,0xaf,0x9c,0x6e,0xb9,0xbe,0x45,0xc3,0x56,0xdf,0x47 };
    const uint8_t IV[] = { 0xff,0xe9,0x2c,0xee,0x17,0xed,0x1d,0xb4,0x22,0xfc,0x3f,0xb3,0x89,0xf4,0xf8,0x58 };
    const uint8_t PLAINTEXT[] = { 0x5a };
    const uint8_t CIPHERTEXT[] = { 0x59 };
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

TEST_CASE("CFB8MCT256-DECRYPT-77", "[CFB8][MCT][256][DECRYPT][n77]") {
    const uint8_t KEY[] = { 0x5f,0xf2,0x0a,0x4f,0x88,0xd9,0xee,0x1e,0x6a,0xc5,0x50,0x92,0x9c,0x67,0xfd,0x03,0xbf,0x2e,0xba,0xce,0x24,0xcb,0x51,0xc8,0x64,0xa1,0xc5,0xcc,0xd1,0x22,0xfe,0x1d };
    const uint8_t IV[] = { 0x32,0x3c,0x37,0x0f,0x9e,0xce,0xfe,0x54,0x0a,0x18,0x7b,0x89,0x12,0x74,0x21,0x5a };
    const uint8_t PLAINTEXT[] = { 0x6f };
    const uint8_t CIPHERTEXT[] = { 0xb7 };
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

TEST_CASE("CFB8MCT256-DECRYPT-78", "[CFB8][MCT][256][DECRYPT][n78]") {
    const uint8_t KEY[] = { 0xcb,0x03,0x68,0x9a,0x79,0xb7,0x2b,0x6b,0x5c,0x2e,0x50,0x8f,0x59,0xe1,0x11,0x3a,0xc2,0xf9,0x79,0xe9,0xc1,0xb4,0xde,0x03,0xc7,0x05,0x56,0x60,0x48,0xf2,0x55,0x72 };
    const uint8_t IV[] = { 0x7d,0xd7,0xc3,0x27,0xe5,0x7f,0x8f,0xcb,0xa3,0xa4,0x93,0xac,0x99,0xd0,0xab,0x6f };
    const uint8_t PLAINTEXT[] = { 0xfe };
    const uint8_t CIPHERTEXT[] = { 0x39 };
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

TEST_CASE("CFB8MCT256-DECRYPT-79", "[CFB8][MCT][256][DECRYPT][n79]") {
    const uint8_t KEY[] = { 0x76,0x1f,0xbf,0xa0,0x6e,0xc0,0xb8,0x76,0x8c,0x64,0x31,0x36,0x6f,0x68,0xc8,0xd6,0xc7,0xa7,0xc3,0xc6,0xdf,0x0d,0x8e,0x33,0x2d,0x3f,0x86,0xa7,0xfe,0x7f,0x36,0x8c };
    const uint8_t IV[] = { 0x05,0x5e,0xba,0x2f,0x1e,0xb9,0x50,0x30,0xea,0x3a,0xd0,0xc7,0xb6,0x8d,0x63,0xfe };
    const uint8_t PLAINTEXT[] = { 0xc9 };
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

TEST_CASE("CFB8MCT256-DECRYPT-80", "[CFB8][MCT][256][DECRYPT][n80]") {
    const uint8_t KEY[] = { 0x8c,0x3e,0x97,0x69,0xde,0x27,0x05,0x3f,0x24,0x11,0x82,0x59,0x3b,0x7e,0xc0,0xde,0xdc,0x32,0x8c,0x5b,0x83,0x29,0xc1,0x4c,0xca,0x2a,0xfa,0xbc,0x99,0xe6,0xda,0x45 };
    const uint8_t IV[] = { 0x1b,0x95,0x4f,0x9d,0x5c,0x24,0x4f,0x7f,0xe7,0x15,0x7c,0x1b,0x67,0x99,0xec,0xc9 };
    const uint8_t PLAINTEXT[] = { 0x60 };
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

TEST_CASE("CFB8MCT256-DECRYPT-81", "[CFB8][MCT][256][DECRYPT][n81]") {
    const uint8_t KEY[] = { 0xbe,0x7a,0x02,0x45,0x01,0x91,0x72,0x3f,0x3c,0x1c,0x9b,0x2b,0xeb,0xab,0x88,0x99,0xa3,0x0e,0x1e,0x78,0x75,0xaf,0x7e,0xb8,0x33,0xe9,0x74,0xf7,0x17,0xd9,0x53,0x25 };
    const uint8_t IV[] = { 0x7f,0x3c,0x92,0x23,0xf6,0x86,0xbf,0xf4,0xf9,0xc3,0x8e,0x4b,0x8e,0x3f,0x89,0x60 };
    const uint8_t PLAINTEXT[] = { 0xca };
    const uint8_t CIPHERTEXT[] = { 0x47 };
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

TEST_CASE("CFB8MCT256-DECRYPT-82", "[CFB8][MCT][256][DECRYPT][n82]") {
    const uint8_t KEY[] = { 0x42,0x07,0x3f,0x60,0xd0,0xfe,0x0c,0xc5,0xc8,0x6d,0xdf,0x6d,0xd1,0xcc,0x5a,0x13,0x27,0x36,0x20,0x7f,0xca,0xc4,0x20,0xf6,0x68,0x81,0xb9,0x0e,0xed,0x70,0x87,0xef };
    const uint8_t IV[] = { 0x84,0x38,0x3e,0x07,0xbf,0x6b,0x5e,0x4e,0x5b,0x68,0xcd,0xf9,0xfa,0xa9,0xd4,0xca };
    const uint8_t PLAINTEXT[] = { 0x6d };
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

TEST_CASE("CFB8MCT256-DECRYPT-83", "[CFB8][MCT][256][DECRYPT][n83]") {
    const uint8_t KEY[] = { 0x3f,0xf4,0x0d,0xaa,0xbb,0x33,0x6f,0x5e,0x5d,0x5f,0xfb,0xe4,0x3a,0xe6,0xc7,0xfd,0x7c,0x90,0xe0,0xca,0x9d,0x98,0x08,0x4f,0xff,0xda,0x5f,0x9b,0x8c,0xb4,0x9a,0x82 };
    const uint8_t IV[] = { 0x5b,0xa6,0xc0,0xb5,0x57,0x5c,0x28,0xb9,0x97,0x5b,0xe6,0x95,0x61,0xc4,0x1d,0x6d };
    const uint8_t PLAINTEXT[] = { 0xef };
    const uint8_t CIPHERTEXT[] = { 0xee };
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

TEST_CASE("CFB8MCT256-DECRYPT-84", "[CFB8][MCT][256][DECRYPT][n84]") {
    const uint8_t KEY[] = { 0xc6,0x64,0x90,0xab,0x15,0x92,0x9e,0x73,0x2f,0x0d,0x9c,0x45,0x50,0x4e,0x15,0x43,0x70,0x45,0x8c,0x8c,0x67,0xb6,0x8f,0xd0,0xb5,0x4b,0xe7,0xf8,0x8c,0x73,0xa0,0x6d };
    const uint8_t IV[] = { 0x0c,0xd5,0x6c,0x46,0xfa,0x2e,0x87,0x9f,0x4a,0x91,0xb8,0x63,0x00,0xc7,0x3a,0xef };
    const uint8_t PLAINTEXT[] = { 0xf4 };
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

TEST_CASE("CFB8MCT256-DECRYPT-85", "[CFB8][MCT][256][DECRYPT][n85]") {
    const uint8_t KEY[] = { 0xb0,0x12,0x60,0x4a,0x3a,0x7d,0xe9,0x2d,0x31,0xfc,0x83,0x49,0x1a,0x87,0x5a,0xfc,0x2f,0x33,0x28,0x8a,0xf9,0x67,0xee,0xc5,0xa4,0xbd,0xba,0x0d,0xe1,0xe8,0x31,0x99 };
    const uint8_t IV[] = { 0x5f,0x76,0xa4,0x06,0x9e,0xd1,0x61,0x15,0x11,0xf6,0x5d,0xf5,0x6d,0x9b,0x91,0xf4 };
    const uint8_t PLAINTEXT[] = { 0x3e };
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

TEST_CASE("CFB8MCT256-DECRYPT-86", "[CFB8][MCT][256][DECRYPT][n86]") {
    const uint8_t KEY[] = { 0x4c,0x8f,0xe7,0x22,0xfd,0x6f,0xc1,0x1e,0x91,0xa1,0x89,0xfe,0x88,0x91,0xae,0x64,0x68,0x67,0x6f,0xe3,0xc2,0xe6,0x57,0xca,0x2a,0x38,0x71,0xc0,0xba,0xf0,0x9c,0xa7 };
    const uint8_t IV[] = { 0x47,0x54,0x47,0x69,0x3b,0x81,0xb9,0x0f,0x8e,0x85,0xcb,0xcd,0x5b,0x18,0xad,0x3e };
    const uint8_t PLAINTEXT[] = { 0x29 };
    const uint8_t CIPHERTEXT[] = { 0x98 };
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

TEST_CASE("CFB8MCT256-DECRYPT-87", "[CFB8][MCT][256][DECRYPT][n87]") {
    const uint8_t KEY[] = { 0x4a,0xdc,0x6f,0x09,0x5e,0x65,0xc7,0x48,0x4d,0x10,0x3e,0x0e,0x5d,0xac,0xd6,0xcc,0x5c,0x71,0x37,0x03,0x9e,0x49,0xc8,0x84,0xaf,0x52,0x23,0x2d,0xc8,0xfc,0xd4,0x8e };
    const uint8_t IV[] = { 0x34,0x16,0x58,0xe0,0x5c,0xaf,0x9f,0x4e,0x85,0x6a,0x52,0xed,0x72,0x0c,0x48,0x29 };
    const uint8_t PLAINTEXT[] = { 0xf3 };
    const uint8_t CIPHERTEXT[] = { 0xa8 };
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

TEST_CASE("CFB8MCT256-DECRYPT-88", "[CFB8][MCT][256][DECRYPT][n88]") {
    const uint8_t KEY[] = { 0x23,0xaa,0x48,0x3e,0x31,0x41,0x04,0xcb,0x17,0x9e,0x19,0x15,0x92,0x66,0x8f,0x34,0xca,0xbf,0x29,0x48,0x56,0x4d,0xb9,0xb1,0x7b,0xd6,0x93,0x01,0x5b,0xf4,0x28,0x7d };
    const uint8_t IV[] = { 0x96,0xce,0x1e,0x4b,0xc8,0x04,0x71,0x35,0xd4,0x84,0xb0,0x2c,0x93,0x08,0xfc,0xf3 };
    const uint8_t PLAINTEXT[] = { 0x49 };
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

TEST_CASE("CFB8MCT256-DECRYPT-89", "[CFB8][MCT][256][DECRYPT][n89]") {
    const uint8_t KEY[] = { 0xc9,0x3a,0x9a,0x0a,0x95,0x49,0x0e,0x63,0x71,0x2b,0x35,0x8c,0xb4,0x87,0xb7,0xcb,0x57,0x3b,0x48,0x8b,0xb0,0x97,0x99,0xcc,0x1a,0xfa,0x7c,0x97,0xe2,0x17,0x25,0x34 };
    const uint8_t IV[] = { 0x9d,0x84,0x61,0xc3,0xe6,0xda,0x20,0x7d,0x61,0x2c,0xef,0x96,0xb9,0xe3,0x0d,0x49 };
    const uint8_t PLAINTEXT[] = { 0x75 };
    const uint8_t CIPHERTEXT[] = { 0xff };
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

TEST_CASE("CFB8MCT256-DECRYPT-90", "[CFB8][MCT][256][DECRYPT][n90]") {
    const uint8_t KEY[] = { 0xf6,0x41,0xe9,0x1a,0x43,0x1c,0x33,0x9a,0x7a,0x23,0xab,0xed,0x14,0x3e,0x16,0xf2,0x61,0x8c,0x73,0xfc,0x5b,0x07,0xeb,0x2e,0x54,0xb8,0x02,0xf3,0xb8,0xac,0x8f,0x41 };
    const uint8_t IV[] = { 0x36,0xb7,0x3b,0x77,0xeb,0x90,0x72,0xe2,0x4e,0x42,0x7e,0x64,0x5a,0xbb,0xaa,0x75 };
    const uint8_t PLAINTEXT[] = { 0x58 };
    const uint8_t CIPHERTEXT[] = { 0x39 };
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

TEST_CASE("CFB8MCT256-DECRYPT-91", "[CFB8][MCT][256][DECRYPT][n91]") {
    const uint8_t KEY[] = { 0x87,0xf8,0x5d,0x33,0xa6,0x0b,0x73,0x59,0x36,0xa6,0x21,0x4d,0x67,0x39,0x22,0x02,0x7f,0x51,0x67,0xd1,0x3f,0x3a,0x68,0x24,0x48,0x8c,0x7d,0x84,0x04,0xe1,0x02,0x19 };
    const uint8_t IV[] = { 0x1e,0xdd,0x14,0x2d,0x64,0x3d,0x83,0x0a,0x1c,0x34,0x7f,0x77,0xbc,0x4d,0x8d,0x58 };
    const uint8_t PLAINTEXT[] = { 0x7d };
    const uint8_t CIPHERTEXT[] = { 0xf0 };
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

TEST_CASE("CFB8MCT256-DECRYPT-92", "[CFB8][MCT][256][DECRYPT][n92]") {
    const uint8_t KEY[] = { 0x90,0x49,0xd5,0xe3,0x09,0x81,0x0b,0xb0,0xe5,0x5f,0x1d,0x38,0xa2,0xa7,0x83,0x27,0xaa,0x67,0xa6,0xc4,0xed,0xe6,0xe1,0xec,0xe6,0x8a,0xa3,0x3e,0x95,0xd5,0x62,0x64 };
    const uint8_t IV[] = { 0xd5,0x36,0xc1,0x15,0xd2,0xdc,0x89,0xc8,0xae,0x06,0xde,0xba,0x91,0x34,0x60,0x7d };
    const uint8_t PLAINTEXT[] = { 0x06 };
    const uint8_t CIPHERTEXT[] = { 0x25 };
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

TEST_CASE("CFB8MCT256-DECRYPT-93", "[CFB8][MCT][256][DECRYPT][n93]") {
    const uint8_t KEY[] = { 0x6f,0x03,0x23,0x91,0x28,0xc7,0x8b,0x48,0x96,0x70,0xe8,0xed,0x43,0x87,0x98,0x3f,0xb4,0x1a,0xad,0x7b,0x15,0x36,0xb3,0x58,0x94,0xfd,0x04,0x3c,0x26,0x0a,0x08,0x62 };
    const uint8_t IV[] = { 0x1e,0x7d,0x0b,0xbf,0xf8,0xd0,0x52,0xb4,0x72,0x77,0xa7,0x02,0xb3,0xdf,0x6a,0x06 };
    const uint8_t PLAINTEXT[] = { 0xae };
    const uint8_t CIPHERTEXT[] = { 0x18 };
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

TEST_CASE("CFB8MCT256-DECRYPT-94", "[CFB8][MCT][256][DECRYPT][n94]") {
    const uint8_t KEY[] = { 0xeb,0x5d,0xfc,0x00,0x9a,0x7a,0x11,0x31,0x93,0x33,0xd1,0x35,0xf6,0xfa,0x39,0xbf,0x50,0x8a,0x8c,0xe3,0x8c,0xe1,0x9b,0xa0,0x5c,0xda,0xa8,0xc1,0x24,0x5d,0x61,0xcc };
    const uint8_t IV[] = { 0xe4,0x90,0x21,0x98,0x99,0xd7,0x28,0xf8,0xc8,0x27,0xac,0xfd,0x02,0x57,0x69,0xae };
    const uint8_t PLAINTEXT[] = { 0x5b };
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

TEST_CASE("CFB8MCT256-DECRYPT-95", "[CFB8][MCT][256][DECRYPT][n95]") {
    const uint8_t KEY[] = { 0xc3,0x26,0xeb,0xde,0xf3,0xfb,0x56,0x92,0x54,0x7c,0xc0,0x4e,0x48,0xe9,0x8b,0x8a,0xf5,0xd1,0xcd,0xc9,0x86,0x73,0x34,0x4b,0x1d,0xb0,0x31,0xd5,0xb2,0xac,0x64,0x97 };
    const uint8_t IV[] = { 0xa5,0x5b,0x41,0x2a,0x0a,0x92,0xaf,0xeb,0x41,0x6a,0x99,0x14,0x96,0xf1,0x05,0x5b };
    const uint8_t PLAINTEXT[] = { 0x8a };
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

TEST_CASE("CFB8MCT256-DECRYPT-96", "[CFB8][MCT][256][DECRYPT][n96]") {
    const uint8_t KEY[] = { 0x39,0x5e,0x7c,0x6d,0x19,0x4b,0x77,0x8e,0x6e,0xb2,0x69,0xa9,0x50,0xa7,0xc4,0x33,0xa7,0x21,0xf5,0x1f,0xf1,0x86,0x93,0x0a,0x3e,0x02,0x2d,0x0a,0xa6,0xd0,0xc8,0x1d };
    const uint8_t IV[] = { 0x52,0xf0,0x38,0xd6,0x77,0xf5,0xa7,0x41,0x23,0xb2,0x1c,0xdf,0x14,0x7c,0xac,0x8a };
    const uint8_t PLAINTEXT[] = { 0xad };
    const uint8_t CIPHERTEXT[] = { 0xb9 };
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

TEST_CASE("CFB8MCT256-DECRYPT-97", "[CFB8][MCT][256][DECRYPT][n97]") {
    const uint8_t KEY[] = { 0x1d,0x1d,0xb0,0xc5,0x9c,0xf3,0x26,0x40,0x4a,0x00,0xd7,0x2a,0x86,0xcf,0xe4,0xdd,0x1b,0xaa,0x32,0xe4,0xa1,0x11,0x31,0x54,0x8f,0x3c,0xef,0xeb,0x37,0xf5,0x55,0xb0 };
    const uint8_t IV[] = { 0xbc,0x8b,0xc7,0xfb,0x50,0x97,0xa2,0x5e,0xb1,0x3e,0xc2,0xe1,0x91,0x25,0x9d,0xad };
    const uint8_t PLAINTEXT[] = { 0xa0 };
    const uint8_t CIPHERTEXT[] = { 0xee };
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

TEST_CASE("CFB8MCT256-DECRYPT-98", "[CFB8][MCT][256][DECRYPT][n98]") {
    const uint8_t KEY[] = { 0x75,0x1e,0xe7,0xfa,0x2a,0x48,0x90,0x4b,0x69,0xdd,0xb9,0x59,0x98,0x33,0x9e,0x8c,0xe3,0xf5,0x30,0x04,0x29,0xd9,0x2a,0x4c,0xe4,0xcf,0xaa,0x7b,0x32,0x7f,0x23,0x10 };
    const uint8_t IV[] = { 0xf8,0x5f,0x02,0xe0,0x88,0xc8,0x1b,0x18,0x6b,0xf3,0x45,0x90,0x05,0x8a,0x76,0xa0 };
    const uint8_t PLAINTEXT[] = { 0x4c };
    const uint8_t CIPHERTEXT[] = { 0x51 };
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

TEST_CASE("CFB8MCT256-DECRYPT-99", "[CFB8][MCT][256][DECRYPT][n99]") {
    const uint8_t KEY[] = { 0x68,0xe8,0xe8,0xdd,0x75,0x5f,0xb6,0x51,0x23,0x15,0x13,0xc7,0x94,0x05,0xe7,0x14,0x19,0xc3,0x1d,0x1b,0x6d,0x69,0xea,0xc2,0xce,0x31,0xce,0xf5,0x3c,0xd9,0x70,0x5c };
    const uint8_t IV[] = { 0xfa,0x36,0x2d,0x1f,0x44,0xb0,0xc0,0x8e,0x2a,0xfe,0x64,0x8e,0x0e,0xa6,0x53,0x4c };
    const uint8_t PLAINTEXT[] = { 0xa4 };
    const uint8_t CIPHERTEXT[] = { 0x98 };
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

