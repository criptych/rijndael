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

TEST_CASE("CFB8MCT192-ENCRYPT-0", "[CFB8][MCT][192][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0xdc,0x66,0xd5,0xcc,0xce,0x06,0xd4,0x7f,0xee,0x3f,0xa2,0xeb,0x65,0xe2,0xdc,0x0b,0xd8,0x53,0x6d,0xf2,0x9a,0xe8,0x5c,0x54 };
    const uint8_t IV[] = { 0xc3,0xca,0xee,0x0b,0x8e,0x23,0xf4,0x00,0xcd,0x47,0x2d,0xae,0xfc,0x4b,0xa2,0x04 };
    const uint8_t PLAINTEXT[] = { 0x92 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-1", "[CFB8][MCT][192][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0x82,0x70,0xa9,0x44,0x87,0x3f,0x6e,0xb0,0xd8,0xe3,0x6d,0xcd,0x0e,0x33,0xd0,0xb6,0xb0,0xb9,0x87,0x1d,0xc0,0x30,0xfc,0x9a };
    const uint8_t IV[] = { 0x36,0xdc,0xcf,0x26,0x6b,0xd1,0x0c,0xbd,0x68,0xea,0xea,0xef,0x5a,0xd8,0xa0,0xce };
    const uint8_t PLAINTEXT[] = { 0xcf };
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

TEST_CASE("CFB8MCT192-ENCRYPT-2", "[CFB8][MCT][192][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0xf7,0xcc,0x9f,0xdf,0x3b,0x19,0x81,0x21,0xc2,0x28,0xc8,0x89,0x95,0x8d,0xeb,0x0b,0xf9,0x54,0x66,0xfc,0xca,0x66,0xe1,0x55 };
    const uint8_t IV[] = { 0x1a,0xcb,0xa5,0x44,0x9b,0xbe,0x3b,0xbd,0x49,0xed,0xe1,0xe1,0x0a,0x56,0x1d,0xcf };
    const uint8_t PLAINTEXT[] = { 0x91 };
    const uint8_t CIPHERTEXT[] = { 0x4d };
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

TEST_CASE("CFB8MCT192-ENCRYPT-3", "[CFB8][MCT][192][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0xa4,0x16,0xaf,0xff,0x5c,0xd6,0x32,0x8a,0xd2,0x4d,0xf8,0x7e,0xf8,0x80,0xfd,0xcc,0xe3,0x23,0x7c,0x90,0xa7,0xb6,0xb7,0x18 };
    const uint8_t IV[] = { 0x10,0x65,0x30,0xf7,0x6d,0x0d,0x16,0xc7,0x1a,0x77,0x1a,0x6c,0x6d,0xd0,0x56,0x4d };
    const uint8_t PLAINTEXT[] = { 0xab };
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

TEST_CASE("CFB8MCT192-ENCRYPT-4", "[CFB8][MCT][192][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0x56,0xdb,0x45,0x1d,0x2d,0x90,0xf5,0x16,0xf6,0x3d,0x49,0xda,0xa9,0xb6,0xb2,0x58,0x66,0x63,0x2d,0x25,0x53,0x0d,0x1e,0xcf };
    const uint8_t IV[] = { 0x24,0x70,0xb1,0xa4,0x51,0x36,0x4f,0x94,0x85,0x40,0x51,0xb5,0xf4,0xbb,0xa9,0xd7 };
    const uint8_t PLAINTEXT[] = { 0x9c };
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

TEST_CASE("CFB8MCT192-ENCRYPT-5", "[CFB8][MCT][192][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0xf4,0xb8,0x93,0x67,0xcd,0x57,0x5c,0x3f,0xda,0xc0,0x7b,0x7e,0x97,0xa6,0x8c,0xd2,0xb1,0xbc,0xb7,0xdc,0x07,0x9f,0x16,0xd9 };
    const uint8_t IV[] = { 0x2c,0xfd,0x32,0xa4,0x3e,0x10,0x3e,0x8a,0xd7,0xdf,0x9a,0xf9,0x54,0x92,0x08,0x16 };
    const uint8_t PLAINTEXT[] = { 0x29 };
    const uint8_t CIPHERTEXT[] = { 0x3d };
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

TEST_CASE("CFB8MCT192-ENCRYPT-6", "[CFB8][MCT][192][ENCRYPT][n6]") {
    const uint8_t KEY[] = { 0x05,0x42,0x39,0x7e,0x2e,0x47,0xd2,0x1f,0x8e,0xc2,0x88,0x2c,0x1e,0x17,0xcb,0x85,0x04,0x13,0xce,0x29,0xbd,0x5d,0x45,0xe4 };
    const uint8_t IV[] = { 0x54,0x02,0xf3,0x52,0x89,0xb1,0x47,0x57,0xb5,0xaf,0x79,0xf5,0xba,0xc2,0x53,0x3d };
    const uint8_t PLAINTEXT[] = { 0x20 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-7", "[CFB8][MCT][192][ENCRYPT][n7]") {
    const uint8_t KEY[] = { 0xee,0x2c,0xfa,0x53,0x76,0x54,0xa0,0x29,0x43,0x8a,0xee,0x47,0x0c,0xcf,0x91,0x2b,0x94,0x7c,0xfa,0xe1,0xa6,0xd8,0xb6,0xd6 };
    const uint8_t IV[] = { 0xcd,0x48,0x66,0x6b,0x12,0xd8,0x5a,0xae,0x90,0x6f,0x34,0xc8,0x1b,0x85,0xf3,0x32 };
    const uint8_t PLAINTEXT[] = { 0x36 };
    const uint8_t CIPHERTEXT[] = { 0x4d };
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

TEST_CASE("CFB8MCT192-ENCRYPT-8", "[CFB8][MCT][192][ENCRYPT][n8]") {
    const uint8_t KEY[] = { 0x56,0x54,0x73,0x5a,0x7f,0xb7,0xee,0xb7,0xe8,0x92,0x12,0x7e,0x49,0x9a,0xa9,0xf3,0x92,0xac,0x86,0xdd,0x31,0xa2,0x31,0x9b };
    const uint8_t IV[] = { 0xab,0x18,0xfc,0x39,0x45,0x55,0x38,0xd8,0x06,0xd0,0x7c,0x3c,0x97,0x7a,0x87,0x4d };
    const uint8_t PLAINTEXT[] = { 0x9e };
    const uint8_t CIPHERTEXT[] = { 0x84 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-9", "[CFB8][MCT][192][ENCRYPT][n9]") {
    const uint8_t KEY[] = { 0x99,0x06,0x68,0xbe,0xae,0xc6,0xfa,0x31,0xf9,0x8a,0xfe,0xbc,0x89,0xb7,0x12,0xf9,0x79,0x34,0x63,0xac,0x34,0xf4,0x85,0x1f };
    const uint8_t IV[] = { 0x11,0x18,0xec,0xc2,0xc0,0x2d,0xbb,0x0a,0xeb,0x98,0xe5,0x71,0x05,0x56,0xb4,0x84 };
    const uint8_t PLAINTEXT[] = { 0x86 };
    const uint8_t CIPHERTEXT[] = { 0x1e };
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

TEST_CASE("CFB8MCT192-ENCRYPT-10", "[CFB8][MCT][192][ENCRYPT][n10]") {
    const uint8_t KEY[] = { 0xf6,0xde,0x71,0x3e,0x6c,0xa5,0xa1,0x81,0xb3,0xc1,0xa3,0xc6,0xa4,0x13,0x85,0xdb,0x97,0xa1,0x6f,0x0a,0x44,0xe7,0x68,0x01 };
    const uint8_t IV[] = { 0x4a,0x4b,0x5d,0x7a,0x2d,0xa4,0x97,0x22,0xee,0x95,0x0c,0xa6,0x70,0x13,0xed,0x1e };
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

TEST_CASE("CFB8MCT192-ENCRYPT-11", "[CFB8][MCT][192][ENCRYPT][n11]") {
    const uint8_t KEY[] = { 0x76,0x33,0x3f,0xd2,0xe3,0x30,0x19,0x9b,0xbe,0x9c,0x4e,0xfb,0x4c,0xaf,0x62,0xc4,0xbc,0xf5,0x9b,0xba,0x23,0x61,0xf0,0x5f };
    const uint8_t IV[] = { 0x0d,0x5d,0xed,0x3d,0xe8,0xbc,0xe7,0x1f,0x2b,0x54,0xf4,0xb0,0x67,0x86,0x98,0x5e };
    const uint8_t PLAINTEXT[] = { 0x1a };
    const uint8_t CIPHERTEXT[] = { 0xca };
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

TEST_CASE("CFB8MCT192-ENCRYPT-12", "[CFB8][MCT][192][ENCRYPT][n12]") {
    const uint8_t KEY[] = { 0x66,0xb7,0x60,0xe1,0x8c,0x5e,0x15,0xe0,0xaf,0x6e,0x67,0x0d,0x3c,0xc2,0xe2,0x92,0x40,0x36,0x90,0x69,0xb9,0x10,0x7a,0x95 };
    const uint8_t IV[] = { 0x11,0xf2,0x29,0xf6,0x70,0x6d,0x80,0x56,0xfc,0xc3,0x0b,0xd3,0x9a,0x71,0x8a,0xca };
    const uint8_t PLAINTEXT[] = { 0x7b };
    const uint8_t CIPHERTEXT[] = { 0xb8 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-13", "[CFB8][MCT][192][ENCRYPT][n13]") {
    const uint8_t KEY[] = { 0x6f,0x1b,0x74,0xe3,0xc2,0x00,0x0f,0x29,0x9f,0xb1,0x5f,0xaf,0xc9,0x89,0x36,0xca,0xf9,0x15,0xff,0x81,0x0c,0x22,0x00,0x2d };
    const uint8_t IV[] = { 0x30,0xdf,0x38,0xa2,0xf5,0x4b,0xd4,0x58,0xb9,0x23,0x6f,0xe8,0xb5,0x32,0x7a,0xb8 };
    const uint8_t PLAINTEXT[] = { 0xc9 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-14", "[CFB8][MCT][192][ENCRYPT][n14]") {
    const uint8_t KEY[] = { 0xd4,0x1c,0xb3,0xe7,0xa8,0x95,0x2f,0x77,0xe6,0xa9,0x06,0x8c,0xdb,0x08,0x04,0xa0,0xbd,0xee,0x8f,0x5f,0x19,0xeb,0xc6,0x90 };
    const uint8_t IV[] = { 0x79,0x18,0x59,0x23,0x12,0x81,0x32,0x6a,0x44,0xfb,0x70,0xde,0x15,0xc9,0xc6,0xbd };
    const uint8_t PLAINTEXT[] = { 0x5e };
    const uint8_t CIPHERTEXT[] = { 0x97 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-15", "[CFB8][MCT][192][ENCRYPT][n15]") {
    const uint8_t KEY[] = { 0x1b,0x75,0x19,0x10,0x32,0x14,0x80,0xc4,0x15,0x69,0x5f,0x36,0xa2,0x95,0x58,0xca,0xb5,0x6a,0xaa,0xb2,0x4c,0x90,0x4e,0x07 };
    const uint8_t IV[] = { 0xf3,0xc0,0x59,0xba,0x79,0x9d,0x5c,0x6a,0x08,0x84,0x25,0xed,0x55,0x7b,0x88,0x97 };
    const uint8_t PLAINTEXT[] = { 0xb3 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-16", "[CFB8][MCT][192][ENCRYPT][n16]") {
    const uint8_t KEY[] = { 0xe5,0xfc,0x7c,0x69,0xb7,0x94,0x7d,0x23,0xbe,0x17,0x34,0x58,0x0c,0x3e,0x84,0xc7,0x71,0xc7,0x6f,0x26,0xc1,0x9e,0x42,0xa2 };
    const uint8_t IV[] = { 0xab,0x7e,0x6b,0x6e,0xae,0xab,0xdc,0x0d,0xc4,0xad,0xc5,0x94,0x8d,0x0e,0x0c,0xa5 };
    const uint8_t PLAINTEXT[] = { 0xe7 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-17", "[CFB8][MCT][192][ENCRYPT][n17]") {
    const uint8_t KEY[] = { 0x1d,0x30,0x58,0x89,0xef,0x8f,0xda,0x9c,0x90,0x91,0xf6,0xeb,0xf6,0x70,0xf9,0x84,0x27,0xb4,0xd7,0xd2,0xdf,0x51,0x46,0x1d };
    const uint8_t IV[] = { 0x2e,0x86,0xc2,0xb3,0xfa,0x4e,0x7d,0x43,0x56,0x73,0xb8,0xf4,0x1e,0xcf,0x04,0xbf };
    const uint8_t PLAINTEXT[] = { 0xbf };
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

TEST_CASE("CFB8MCT192-ENCRYPT-18", "[CFB8][MCT][192][ENCRYPT][n18]") {
    const uint8_t KEY[] = { 0x09,0xbe,0x2f,0xdc,0x90,0x90,0x32,0x4a,0xdf,0x9c,0x3c,0x8e,0x92,0xd7,0x03,0x7a,0xd0,0xb3,0xf5,0xda,0xc4,0x33,0xbf,0x61 };
    const uint8_t IV[] = { 0x4f,0x0d,0xca,0x65,0x64,0xa7,0xfa,0xfe,0xf7,0x07,0x22,0x08,0x1b,0x62,0xf9,0x7c };
    const uint8_t PLAINTEXT[] = { 0xd6 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-19", "[CFB8][MCT][192][ENCRYPT][n19]") {
    const uint8_t KEY[] = { 0xdc,0xff,0x87,0x79,0xeb,0x72,0x7c,0x93,0xfe,0x60,0xcd,0x8e,0x1c,0xd1,0x5d,0xca,0x4c,0xa2,0xd9,0xb6,0x0f,0xe9,0x6d,0x72 };
    const uint8_t IV[] = { 0x21,0xfc,0xf1,0x00,0x8e,0x06,0x5e,0xb0,0x9c,0x11,0x2c,0x6c,0xcb,0xda,0xd2,0x13 };
    const uint8_t PLAINTEXT[] = { 0xd9 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-20", "[CFB8][MCT][192][ENCRYPT][n20]") {
    const uint8_t KEY[] = { 0xf8,0x45,0xa7,0x31,0x31,0xb2,0xb5,0x73,0xbb,0x1c,0x3d,0xb4,0x8c,0x93,0x68,0x0c,0x79,0xc2,0x59,0xde,0xc0,0x33,0xf1,0xaf };
    const uint8_t IV[] = { 0x45,0x7c,0xf0,0x3a,0x90,0x42,0x35,0xc6,0x35,0x60,0x80,0x68,0xcf,0xda,0x9c,0xdd };
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

TEST_CASE("CFB8MCT192-ENCRYPT-21", "[CFB8][MCT][192][ENCRYPT][n21]") {
    const uint8_t KEY[] = { 0x8c,0x37,0x2b,0xc0,0xa1,0x51,0xfe,0x7e,0x19,0x6e,0xec,0x86,0x32,0xfe,0x59,0x95,0x80,0x19,0x53,0xc7,0xdc,0xa1,0x25,0x70 };
    const uint8_t IV[] = { 0xa2,0x72,0xd1,0x32,0xbe,0x6d,0x31,0x99,0xf9,0xdb,0x0a,0x19,0x1c,0x92,0xd4,0xdf };
    const uint8_t PLAINTEXT[] = { 0x0d };
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

TEST_CASE("CFB8MCT192-ENCRYPT-22", "[CFB8][MCT][192][ENCRYPT][n22]") {
    const uint8_t KEY[] = { 0x46,0x8d,0xf9,0xe0,0x96,0x94,0x11,0xad,0x7c,0xee,0xcc,0x12,0x70,0x00,0x73,0x96,0xc6,0x29,0xfe,0x30,0xf1,0x37,0xb0,0x8a };
    const uint8_t IV[] = { 0x65,0x80,0x20,0x94,0x42,0xfe,0x2a,0x03,0x46,0x30,0xad,0xf7,0x2d,0x96,0x95,0xfa };
    const uint8_t PLAINTEXT[] = { 0xd3 };
    const uint8_t CIPHERTEXT[] = { 0x0e };
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

TEST_CASE("CFB8MCT192-ENCRYPT-23", "[CFB8][MCT][192][ENCRYPT][n23]") {
    const uint8_t KEY[] = { 0xbe,0xf9,0x19,0xb7,0xdf,0x38,0x5b,0xc2,0x80,0x8c,0x4b,0x47,0x1d,0x95,0x2d,0x20,0x64,0x39,0x98,0xfa,0x9d,0x11,0x18,0x84 };
    const uint8_t IV[] = { 0xfc,0x62,0x87,0x55,0x6d,0x95,0x5e,0xb6,0xa2,0x10,0x66,0xca,0x6c,0x26,0xa8,0x0e };
    const uint8_t PLAINTEXT[] = { 0x6f };
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

TEST_CASE("CFB8MCT192-ENCRYPT-24", "[CFB8][MCT][192][ENCRYPT][n24]") {
    const uint8_t KEY[] = { 0x31,0x69,0x27,0x2d,0x9d,0x96,0x58,0xb8,0x9a,0xa1,0x91,0xd7,0xdf,0x87,0xa9,0x6a,0x8c,0xff,0x76,0x81,0x80,0xa0,0x5c,0xfa };
    const uint8_t IV[] = { 0x1a,0x2d,0xda,0x90,0xc2,0x12,0x84,0x4a,0xe8,0xc6,0xee,0x7b,0x1d,0xb1,0x44,0x7e };
    const uint8_t PLAINTEXT[] = { 0x7a };
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

TEST_CASE("CFB8MCT192-ENCRYPT-25", "[CFB8][MCT][192][ENCRYPT][n25]") {
    const uint8_t KEY[] = { 0x1c,0x0a,0x9b,0x9c,0xcd,0xf3,0x26,0xb8,0x20,0xd9,0x46,0x77,0x02,0x7c,0xc8,0xe7,0x12,0xbd,0x48,0xd2,0x25,0x2a,0xa9,0xce };
    const uint8_t IV[] = { 0xba,0x78,0xd7,0xa0,0xdd,0xfb,0x61,0x8d,0x9e,0x42,0x3e,0x53,0xa5,0x8a,0xf5,0x34 };
    const uint8_t PLAINTEXT[] = { 0x00 };
    const uint8_t CIPHERTEXT[] = { 0x97 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-26", "[CFB8][MCT][192][ENCRYPT][n26]") {
    const uint8_t KEY[] = { 0x3e,0x7d,0x3e,0xeb,0x57,0x47,0xcd,0x6a,0x47,0xc5,0x39,0x79,0x30,0xcd,0xdd,0x16,0x2d,0x77,0x1e,0x22,0x7c,0x76,0x62,0x59 };
    const uint8_t IV[] = { 0x67,0x1c,0x7f,0x0e,0x32,0xb1,0x15,0xf1,0x3f,0xca,0x56,0xf0,0x59,0x5c,0xcb,0x97 };
    const uint8_t PLAINTEXT[] = { 0xd2 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-27", "[CFB8][MCT][192][ENCRYPT][n27]") {
    const uint8_t KEY[] = { 0xd6,0x12,0x17,0xaa,0x7e,0x8f,0xad,0x32,0xef,0x35,0xe7,0xcb,0x1e,0xa3,0x5b,0x1f,0xc5,0x6e,0x93,0x04,0x5b,0xc9,0x80,0x09 };
    const uint8_t IV[] = { 0xa8,0xf0,0xde,0xb2,0x2e,0x6e,0x86,0x09,0xe8,0x19,0x8d,0x26,0x27,0xbf,0xe2,0x50 };
    const uint8_t PLAINTEXT[] = { 0x58 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-28", "[CFB8][MCT][192][ENCRYPT][n28]") {
    const uint8_t KEY[] = { 0x76,0xa4,0x61,0x91,0xf2,0xa0,0x8a,0xd0,0x24,0xdd,0x40,0x6d,0xa2,0x39,0x26,0xdd,0xa5,0x62,0xa7,0x1e,0x98,0x5e,0xec,0x66 };
    const uint8_t IV[] = { 0xcb,0xe8,0xa7,0xa6,0xbc,0x9a,0x7d,0xc2,0x60,0x0c,0x34,0x1a,0xc3,0x97,0x6c,0x6f };
    const uint8_t PLAINTEXT[] = { 0xe2 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-29", "[CFB8][MCT][192][ENCRYPT][n29]") {
    const uint8_t KEY[] = { 0x9d,0x5e,0x00,0x86,0x46,0x5f,0x4e,0x46,0x8b,0xfc,0x2f,0x40,0x27,0xc1,0xe3,0x80,0x5d,0xee,0x2e,0x64,0x81,0xdb,0xa0,0x0a };
    const uint8_t IV[] = { 0xaf,0x21,0x6f,0x2d,0x85,0xf8,0xc5,0x5d,0xf8,0x8c,0x89,0x7a,0x19,0x85,0x4c,0x6c };
    const uint8_t PLAINTEXT[] = { 0x96 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-30", "[CFB8][MCT][192][ENCRYPT][n30]") {
    const uint8_t KEY[] = { 0x60,0xc3,0xdf,0x85,0x55,0x42,0x27,0xcb,0x8c,0x20,0x2a,0x1b,0xbe,0x84,0xb1,0xb4,0x53,0x4c,0x65,0x4a,0x2f,0x32,0x33,0xfd };
    const uint8_t IV[] = { 0x07,0xdc,0x05,0x5b,0x99,0x45,0x52,0x34,0x0e,0xa2,0x4b,0x2e,0xae,0xe9,0x93,0xf7 };
    const uint8_t PLAINTEXT[] = { 0x8d };
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

TEST_CASE("CFB8MCT192-ENCRYPT-31", "[CFB8][MCT][192][ENCRYPT][n31]") {
    const uint8_t KEY[] = { 0x4d,0x10,0xd6,0x07,0x23,0x9c,0xd0,0x32,0x62,0x02,0xcd,0x7c,0xb3,0x53,0x13,0x35,0x56,0x63,0xa9,0x33,0x1d,0xbb,0x79,0x78 };
    const uint8_t IV[] = { 0xee,0x22,0xe7,0x67,0x0d,0xd7,0xa2,0x81,0x05,0x2f,0xcc,0x79,0x32,0x89,0x4a,0x85 };
    const uint8_t PLAINTEXT[] = { 0xf9 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-32", "[CFB8][MCT][192][ENCRYPT][n32]") {
    const uint8_t KEY[] = { 0xd4,0x70,0x7a,0xdd,0x3f,0xa3,0x67,0x86,0x06,0xa9,0x4a,0x13,0x09,0xb1,0x50,0xf2,0x21,0x4f,0xbd,0x47,0xe6,0x3e,0x99,0xf2 };
    const uint8_t IV[] = { 0x64,0xab,0x87,0x6f,0xba,0xe2,0x43,0xc7,0x77,0x2c,0x14,0x74,0xfb,0x85,0xe0,0x8a };
    const uint8_t PLAINTEXT[] = { 0xb4 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-33", "[CFB8][MCT][192][ENCRYPT][n33]") {
    const uint8_t KEY[] = { 0x51,0x76,0x98,0x1b,0x1d,0xf3,0x03,0xce,0x99,0x38,0xde,0xf2,0x52,0x2a,0xc8,0x69,0x07,0xb7,0x74,0xc2,0x9b,0xd8,0xbb,0x87 };
    const uint8_t IV[] = { 0x9f,0x91,0x94,0xe1,0x5b,0x9b,0x98,0x9b,0x26,0xf8,0xc9,0x85,0x7d,0xe6,0x22,0x75 };
    const uint8_t PLAINTEXT[] = { 0x48 };
    const uint8_t CIPHERTEXT[] = { 0x2e };
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

TEST_CASE("CFB8MCT192-ENCRYPT-34", "[CFB8][MCT][192][ENCRYPT][n34]") {
    const uint8_t KEY[] = { 0x7d,0x53,0xd4,0x70,0xef,0x3f,0xa4,0xf1,0xcc,0xb5,0xe4,0x5c,0x79,0x51,0x8c,0x20,0x0c,0x53,0x97,0x5d,0xf3,0x85,0x17,0xa9 };
    const uint8_t IV[] = { 0x55,0x8d,0x3a,0xae,0x2b,0x7b,0x44,0x49,0x0b,0xe4,0xe3,0x9f,0x68,0x5d,0xac,0x2e };
    const uint8_t PLAINTEXT[] = { 0x3f };
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

TEST_CASE("CFB8MCT192-ENCRYPT-35", "[CFB8][MCT][192][ENCRYPT][n35]") {
    const uint8_t KEY[] = { 0xbb,0x80,0x30,0x71,0x61,0x9d,0xd4,0xf6,0x82,0x56,0x88,0x99,0x3e,0x5f,0x06,0x76,0x10,0xa7,0xb0,0xee,0x31,0xe0,0x26,0x27 };
    const uint8_t IV[] = { 0x4e,0xe3,0x6c,0xc5,0x47,0x0e,0x8a,0x56,0x1c,0xf4,0x27,0xb3,0xc2,0x65,0x31,0x8e };
    const uint8_t PLAINTEXT[] = { 0x07 };
    const uint8_t CIPHERTEXT[] = { 0x2d };
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

TEST_CASE("CFB8MCT192-ENCRYPT-36", "[CFB8][MCT][192][ENCRYPT][n36]") {
    const uint8_t KEY[] = { 0xa4,0x0b,0xd2,0x6f,0xb6,0xd9,0x0f,0x66,0x5c,0xc7,0x2a,0xaa,0x98,0x78,0x2a,0xed,0x30,0x69,0xb2,0xb9,0x3c,0x06,0xf0,0x0a };
    const uint8_t IV[] = { 0xde,0x91,0xa2,0x33,0xa6,0x27,0x2c,0x9b,0x20,0xce,0x02,0x57,0x0d,0xe6,0xd6,0x2d };
    const uint8_t PLAINTEXT[] = { 0x90 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-37", "[CFB8][MCT][192][ENCRYPT][n37]") {
    const uint8_t KEY[] = { 0x0d,0xd8,0x48,0x20,0xed,0x1f,0x14,0x3e,0xeb,0x6e,0xce,0x93,0x53,0xcc,0x78,0xe6,0x86,0x40,0xbc,0x29,0xaa,0x67,0x94,0x43 };
    const uint8_t IV[] = { 0xb7,0xa9,0xe4,0x39,0xcb,0xb4,0x52,0x0b,0xb6,0x29,0x0e,0x90,0x96,0x61,0x64,0x49 };
    const uint8_t PLAINTEXT[] = { 0x58 };
    const uint8_t CIPHERTEXT[] = { 0xd0 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-38", "[CFB8][MCT][192][ENCRYPT][n38]") {
    const uint8_t KEY[] = { 0xff,0xa0,0x8b,0x23,0x8d,0x03,0x70,0x53,0x49,0x11,0xb1,0x14,0x3a,0x0f,0x43,0x3b,0xa2,0xce,0x51,0xf7,0x4d,0xfd,0xea,0x93 };
    const uint8_t IV[] = { 0xa2,0x7f,0x7f,0x87,0x69,0xc3,0x3b,0xdd,0x24,0x8e,0xed,0xde,0xe7,0x9a,0x7e,0xd0 };
    const uint8_t PLAINTEXT[] = { 0x6d };
    const uint8_t CIPHERTEXT[] = { 0x3b };
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

TEST_CASE("CFB8MCT192-ENCRYPT-39", "[CFB8][MCT][192][ENCRYPT][n39]") {
    const uint8_t KEY[] = { 0x9e,0xc5,0x05,0x4c,0xf4,0x72,0xcb,0x82,0xe2,0xce,0xbf,0x4a,0xe4,0xc4,0x52,0x70,0x25,0xa0,0x31,0xca,0x80,0x0f,0xc4,0xa8 };
    const uint8_t IV[] = { 0xab,0xdf,0x0e,0x5e,0xde,0xcb,0x11,0x4b,0x87,0x6e,0x60,0x3d,0xcd,0xf2,0x2e,0x3b };
    const uint8_t PLAINTEXT[] = { 0xd1 };
    const uint8_t CIPHERTEXT[] = { 0x7d };
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

TEST_CASE("CFB8MCT192-ENCRYPT-40", "[CFB8][MCT][192][ENCRYPT][n40]") {
    const uint8_t KEY[] = { 0x45,0x74,0xff,0x5c,0x17,0x38,0x7e,0xd3,0x0c,0xf1,0x35,0x7b,0xdd,0xb7,0x4c,0xa4,0xe3,0xcd,0xe6,0x21,0xfc,0x33,0xa3,0xd5 };
    const uint8_t IV[] = { 0xee,0x3f,0x8a,0x31,0x39,0x73,0x1e,0xd4,0xc6,0x6d,0xd7,0xeb,0x7c,0x3c,0x67,0x7d };
    const uint8_t PLAINTEXT[] = { 0x51 };
    const uint8_t CIPHERTEXT[] = { 0x0d };
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

TEST_CASE("CFB8MCT192-ENCRYPT-41", "[CFB8][MCT][192][ENCRYPT][n41]") {
    const uint8_t KEY[] = { 0xfd,0xb4,0x2f,0x4f,0x78,0xbb,0xa9,0x13,0xfa,0xf2,0x54,0x0c,0x7b,0xe5,0x64,0xb4,0xca,0x86,0x0c,0xfc,0xf8,0x47,0x17,0xd8 };
    const uint8_t IV[] = { 0xf6,0x03,0x61,0x77,0xa6,0x52,0x28,0x10,0x29,0x4b,0xea,0xdd,0x04,0x74,0xb4,0x0d };
    const uint8_t PLAINTEXT[] = { 0xc0 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-42", "[CFB8][MCT][192][ENCRYPT][n42]") {
    const uint8_t KEY[] = { 0x7c,0xfd,0x4a,0x17,0xb6,0x5b,0x43,0xf6,0x32,0xe7,0xd4,0x87,0x3e,0x95,0xa0,0x6b,0x23,0x23,0x20,0x66,0x82,0xed,0x88,0x63 };
    const uint8_t IV[] = { 0xc8,0x15,0x80,0x8b,0x45,0x70,0xc4,0xdf,0xe9,0xa5,0x2c,0x9a,0x7a,0xaa,0x9f,0xbb };
    const uint8_t PLAINTEXT[] = { 0xe5 };
    const uint8_t CIPHERTEXT[] = { 0x2e };
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

TEST_CASE("CFB8MCT192-ENCRYPT-43", "[CFB8][MCT][192][ENCRYPT][n43]") {
    const uint8_t KEY[] = { 0x3b,0x4e,0x30,0xe2,0xec,0xa4,0x86,0x26,0x67,0x59,0x03,0x61,0x81,0xe9,0xd2,0x1a,0xdd,0x4b,0x1e,0xd9,0x06,0x88,0x86,0x4d };
    const uint8_t IV[] = { 0x55,0xbe,0xd7,0xe6,0xbf,0x7c,0x72,0x71,0xfe,0x68,0x3e,0xbf,0x84,0x65,0x0e,0x2e };
    const uint8_t PLAINTEXT[] = { 0xd0 };
    const uint8_t CIPHERTEXT[] = { 0x82 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-44", "[CFB8][MCT][192][ENCRYPT][n44]") {
    const uint8_t KEY[] = { 0x37,0xb5,0xef,0x2c,0x57,0xc3,0xb9,0xf6,0xb4,0xf0,0x21,0x5c,0xc8,0xfd,0x12,0xbd,0x6c,0x69,0xd2,0xdf,0xa1,0x81,0x98,0xcf };
    const uint8_t IV[] = { 0xd3,0xa9,0x22,0x3d,0x49,0x14,0xc0,0xa7,0xb1,0x22,0xcc,0x06,0xa7,0x09,0x1e,0x82 };
    const uint8_t PLAINTEXT[] = { 0xd0 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-45", "[CFB8][MCT][192][ENCRYPT][n45]") {
    const uint8_t KEY[] = { 0xe1,0x05,0xac,0xb1,0x3b,0x28,0x6f,0xa0,0xad,0xd6,0x78,0xa5,0x15,0x92,0xec,0x5f,0xcb,0x30,0x12,0x70,0x22,0xeb,0xa9,0x2d };
    const uint8_t IV[] = { 0x19,0x26,0x59,0xf9,0xdd,0x6f,0xfe,0xe2,0xa7,0x59,0xc0,0xaf,0x83,0x6a,0x31,0xe2 };
    const uint8_t PLAINTEXT[] = { 0x56 };
    const uint8_t CIPHERTEXT[] = { 0xb1 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-46", "[CFB8][MCT][192][ENCRYPT][n46]") {
    const uint8_t KEY[] = { 0xdd,0x34,0xba,0x62,0x4c,0x0c,0x53,0x64,0xb5,0x96,0x6d,0xa8,0x82,0xf0,0x18,0xb2,0x1d,0xe3,0xa4,0xe8,0x26,0x09,0x58,0x9c };
    const uint8_t IV[] = { 0x18,0x40,0x15,0x0d,0x97,0x62,0xf4,0xed,0xd6,0xd3,0xb6,0x98,0x04,0xe2,0xf1,0xb1 };
    const uint8_t PLAINTEXT[] = { 0xc4 };
    const uint8_t CIPHERTEXT[] = { 0xd3 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-47", "[CFB8][MCT][192][ENCRYPT][n47]") {
    const uint8_t KEY[] = { 0xbb,0x8a,0x9f,0x85,0x41,0xac,0xfd,0x24,0x64,0xe0,0x7e,0xdd,0x5b,0x60,0xb6,0xe1,0x6f,0x1c,0xc8,0xfb,0xa9,0x36,0x6d,0x4f };
    const uint8_t IV[] = { 0xd1,0x76,0x13,0x75,0xd9,0x90,0xae,0x53,0x72,0xff,0x6c,0x13,0x8f,0x3f,0x35,0xd3 };
    const uint8_t PLAINTEXT[] = { 0x40 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-48", "[CFB8][MCT][192][ENCRYPT][n48]") {
    const uint8_t KEY[] = { 0xca,0xb5,0x5c,0x57,0xab,0x1c,0xaa,0xf1,0xb2,0xff,0x44,0x07,0x95,0x58,0xb8,0xb1,0x83,0x2d,0xb4,0xa8,0x83,0xee,0x1a,0x82 };
    const uint8_t IV[] = { 0xd6,0x1f,0x3a,0xda,0xce,0x38,0x0e,0x50,0xec,0x31,0x7c,0x53,0x2a,0xd8,0x77,0xcd };
    const uint8_t PLAINTEXT[] = { 0xd5 };
    const uint8_t CIPHERTEXT[] = { 0xc1 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-49", "[CFB8][MCT][192][ENCRYPT][n49]") {
    const uint8_t KEY[] = { 0xd5,0xcd,0x10,0xb8,0x20,0xa8,0x30,0x9b,0x77,0x7d,0x29,0x67,0x2c,0x84,0x7a,0xbe,0x25,0xf2,0x02,0xbb,0x1f,0x02,0xeb,0x43 };
    const uint8_t IV[] = { 0xc5,0x82,0x6d,0x60,0xb9,0xdc,0xc2,0x0f,0xa6,0xdf,0xb6,0x13,0x9c,0xec,0xf1,0xc1 };
    const uint8_t PLAINTEXT[] = { 0x6a };
    const uint8_t CIPHERTEXT[] = { 0x7f };
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

TEST_CASE("CFB8MCT192-ENCRYPT-50", "[CFB8][MCT][192][ENCRYPT][n50]") {
    const uint8_t KEY[] = { 0x01,0x03,0x5f,0x78,0x1e,0xc5,0x02,0xea,0x93,0x5c,0xb6,0x1e,0x30,0x86,0x95,0xc0,0xc8,0x7e,0xa1,0x9d,0xe4,0x87,0xbc,0x3c };
    const uint8_t IV[] = { 0xe4,0x21,0x9f,0x79,0x1c,0x02,0xef,0x7e,0xed,0x8c,0xa3,0x26,0xfb,0x85,0x57,0x7f };
    const uint8_t PLAINTEXT[] = { 0x71 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-51", "[CFB8][MCT][192][ENCRYPT][n51]") {
    const uint8_t KEY[] = { 0x65,0xd0,0x5c,0x68,0x50,0xed,0xff,0x45,0xd4,0x5a,0x90,0x0a,0xae,0x1c,0x13,0x01,0x57,0x2b,0x6b,0xf6,0xb0,0x31,0x4a,0xc8 };
    const uint8_t IV[] = { 0x47,0x06,0x26,0x14,0x9e,0x9a,0x86,0xc1,0x9f,0x55,0xca,0x6b,0x54,0xb6,0xf6,0xf4 };
    const uint8_t PLAINTEXT[] = { 0xaf };
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

TEST_CASE("CFB8MCT192-ENCRYPT-52", "[CFB8][MCT][192][ENCRYPT][n52]") {
    const uint8_t KEY[] = { 0x73,0x6e,0x97,0x1a,0x45,0x35,0xac,0x83,0xe5,0x1e,0xa9,0xe1,0x13,0x3a,0x23,0xe2,0x1f,0x39,0x30,0xb4,0xe0,0x99,0x94,0x55 };
    const uint8_t IV[] = { 0x31,0x44,0x39,0xeb,0xbd,0x26,0x30,0xe3,0x48,0x12,0x5b,0x42,0x50,0xa8,0xde,0x9d };
    const uint8_t PLAINTEXT[] = { 0xc6 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-53", "[CFB8][MCT][192][ENCRYPT][n53]") {
    const uint8_t KEY[] = { 0x60,0x75,0x1b,0x85,0xf7,0x48,0xb8,0x7d,0x4f,0x7b,0x96,0x54,0x19,0x64,0xef,0xc1,0x81,0xe1,0x71,0xb4,0xeb,0x02,0xbb,0x0e };
    const uint8_t IV[] = { 0xaa,0x65,0x3f,0xb5,0x0a,0x5e,0xcc,0x23,0x9e,0xd8,0x41,0x00,0x0b,0x9b,0x2f,0x5b };
    const uint8_t PLAINTEXT[] = { 0xfe };
    const uint8_t CIPHERTEXT[] = { 0x0b };
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

TEST_CASE("CFB8MCT192-ENCRYPT-54", "[CFB8][MCT][192][ENCRYPT][n54]") {
    const uint8_t KEY[] = { 0x7f,0x3c,0x78,0xe9,0x84,0x69,0x10,0x9d,0x4d,0x1f,0x0d,0x49,0x37,0x24,0x18,0xc5,0x00,0xb6,0xae,0x39,0x3e,0x26,0x09,0x05 };
    const uint8_t IV[] = { 0x02,0x64,0x9b,0x1d,0x2e,0x40,0xf7,0x04,0x81,0x57,0xdf,0x8d,0xd5,0x24,0xb2,0x0b };
    const uint8_t PLAINTEXT[] = { 0xe0 };
    const uint8_t CIPHERTEXT[] = { 0x76 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-55", "[CFB8][MCT][192][ENCRYPT][n55]") {
    const uint8_t KEY[] = { 0x06,0x5d,0x5e,0x0e,0xdd,0xcb,0x81,0xfe,0xea,0xbc,0x18,0x2d,0xe9,0x79,0xbb,0x85,0x8c,0x23,0x49,0xde,0xd8,0x96,0xd2,0x73 };
    const uint8_t IV[] = { 0xa7,0xa3,0x15,0x64,0xde,0x5d,0xa3,0x40,0x8c,0x95,0xe7,0xe7,0xe6,0xb0,0xdb,0x76 };
    const uint8_t PLAINTEXT[] = { 0x63 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-56", "[CFB8][MCT][192][ENCRYPT][n56]") {
    const uint8_t KEY[] = { 0x87,0x80,0x93,0xd5,0x9d,0xab,0x48,0xc3,0xb2,0x04,0x12,0x66,0x70,0x8b,0x4f,0x5b,0x34,0xb5,0x98,0x7e,0xe7,0xb5,0xaf,0xbe };
    const uint8_t IV[] = { 0x58,0xb8,0x0a,0x4b,0x99,0xf2,0xf4,0xde,0xb8,0x96,0xd1,0xa0,0x3f,0x23,0x7d,0xcd };
    const uint8_t PLAINTEXT[] = { 0x3d };
    const uint8_t CIPHERTEXT[] = { 0x6b };
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

TEST_CASE("CFB8MCT192-ENCRYPT-57", "[CFB8][MCT][192][ENCRYPT][n57]") {
    const uint8_t KEY[] = { 0xca,0xb8,0x05,0x64,0xf9,0x54,0x95,0x30,0x00,0x4c,0xb8,0xe9,0x04,0x80,0x80,0x7a,0x6a,0xdd,0x30,0x84,0x2f,0x08,0x6e,0xd5 };
    const uint8_t IV[] = { 0xb2,0x48,0xaa,0x8f,0x74,0x0b,0xcf,0x21,0x5e,0x68,0xa8,0xfa,0xc8,0xbd,0xc1,0x6b };
    const uint8_t PLAINTEXT[] = { 0xf3 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-58", "[CFB8][MCT][192][ENCRYPT][n58]") {
    const uint8_t KEY[] = { 0x84,0x6d,0xbc,0x32,0x13,0x3e,0x56,0xe6,0xae,0x82,0x3b,0x1a,0xba,0x70,0x5b,0x20,0x07,0x3f,0x9b,0xf2,0x0e,0x75,0x46,0xe7 };
    const uint8_t IV[] = { 0xae,0xce,0x83,0xf3,0xbe,0xf0,0xdb,0x5a,0x6d,0xe2,0xab,0x76,0x21,0x7d,0x28,0x32 };
    const uint8_t PLAINTEXT[] = { 0xd6 };
    const uint8_t CIPHERTEXT[] = { 0x52 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-59", "[CFB8][MCT][192][ENCRYPT][n59]") {
    const uint8_t KEY[] = { 0x8a,0x08,0xf1,0x89,0xde,0x4d,0xa6,0xf3,0x4a,0x37,0x42,0x32,0xcb,0xf9,0x97,0x3e,0x13,0x42,0x2e,0xca,0x76,0x43,0x73,0xb5 };
    const uint8_t IV[] = { 0xe4,0xb5,0x79,0x28,0x71,0x89,0xcc,0x1e,0x14,0x7d,0xb5,0x38,0x78,0x36,0x35,0x52 };
    const uint8_t PLAINTEXT[] = { 0x15 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-60", "[CFB8][MCT][192][ENCRYPT][n60]") {
    const uint8_t KEY[] = { 0xc7,0x53,0x8a,0xdb,0x81,0x20,0xd0,0x62,0x57,0x53,0x76,0xf3,0x1c,0x60,0xbe,0xed,0x6d,0x94,0xc3,0x32,0x4b,0x50,0xb8,0xa8 };
    const uint8_t IV[] = { 0x1d,0x64,0x34,0xc1,0xd7,0x99,0x29,0xd3,0x7e,0xd6,0xed,0xf8,0x3d,0x13,0xcb,0x1d };
    const uint8_t PLAINTEXT[] = { 0x91 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-61", "[CFB8][MCT][192][ENCRYPT][n61]") {
    const uint8_t KEY[] = { 0xc2,0x3f,0x64,0x42,0xb3,0x1e,0x49,0xbc,0x44,0xdd,0x3a,0x39,0x9a,0x5c,0x32,0x20,0x17,0x5b,0x2a,0xf2,0x86,0x10,0x9d,0x17 };
    const uint8_t IV[] = { 0x13,0x8e,0x4c,0xca,0x86,0x3c,0x8c,0xcd,0x7a,0xcf,0xe9,0xc0,0xcd,0x40,0x25,0xbf };
    const uint8_t PLAINTEXT[] = { 0xde };
    const uint8_t CIPHERTEXT[] = { 0x01 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-62", "[CFB8][MCT][192][ENCRYPT][n62]") {
    const uint8_t KEY[] = { 0x78,0x51,0x49,0xeb,0x38,0x5e,0x4a,0x7b,0x1d,0x75,0xcd,0x81,0xdf,0x96,0x79,0x94,0x01,0xe7,0x6e,0x34,0xb0,0x3a,0x19,0x16 };
    const uint8_t IV[] = { 0x59,0xa8,0xf7,0xb8,0x45,0xca,0x4b,0xb4,0x16,0xbc,0x44,0xc6,0x36,0x2a,0x84,0x01 };
    const uint8_t PLAINTEXT[] = { 0xc7 };
    const uint8_t CIPHERTEXT[] = { 0x84 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-63", "[CFB8][MCT][192][ENCRYPT][n63]") {
    const uint8_t KEY[] = { 0x4e,0x23,0xf1,0x56,0xcc,0xfe,0xd4,0x8f,0xde,0x8d,0x72,0x81,0x4f,0xeb,0xe5,0x6a,0x12,0x0a,0xdd,0x34,0x0d,0x25,0x81,0x92 };
    const uint8_t IV[] = { 0xc3,0xf8,0xbf,0x00,0x90,0x7d,0x9c,0xfe,0x13,0xed,0xb3,0x00,0xbd,0x1f,0x98,0x84 };
    const uint8_t PLAINTEXT[] = { 0xf4 };
    const uint8_t CIPHERTEXT[] = { 0x3a };
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

TEST_CASE("CFB8MCT192-ENCRYPT-64", "[CFB8][MCT][192][ENCRYPT][n64]") {
    const uint8_t KEY[] = { 0xdc,0x15,0xd6,0x9b,0x43,0x53,0x6f,0x36,0xe2,0xb4,0x04,0xd7,0x8b,0x38,0x78,0xc8,0x5c,0x9f,0x64,0xf6,0xb5,0xf4,0xbf,0xa8 };
    const uint8_t IV[] = { 0x3c,0x39,0x76,0x56,0xc4,0xd3,0x9d,0xa2,0x4e,0x95,0xb9,0xc2,0xb8,0xd1,0x3e,0x3a };
    const uint8_t PLAINTEXT[] = { 0xb9 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-65", "[CFB8][MCT][192][ENCRYPT][n65]") {
    const uint8_t KEY[] = { 0xd9,0xfa,0x2f,0xf8,0xc6,0xfd,0xf3,0x64,0x54,0x6e,0x7f,0x45,0x97,0x0b,0xe5,0x48,0x29,0x98,0x52,0xa0,0x75,0x3c,0xed,0xb1 };
    const uint8_t IV[] = { 0xb6,0xda,0x7b,0x92,0x1c,0x33,0x9d,0x80,0x75,0x07,0x36,0x56,0xc0,0xc8,0x52,0x19 };
    const uint8_t PLAINTEXT[] = { 0x52 };
    const uint8_t CIPHERTEXT[] = { 0x05 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-66", "[CFB8][MCT][192][ENCRYPT][n66]") {
    const uint8_t KEY[] = { 0x0d,0x1b,0x50,0xb1,0x08,0x08,0xde,0xa8,0x39,0xa2,0xe6,0x26,0x61,0x05,0x84,0xf4,0x41,0x91,0xf4,0xc8,0x97,0xfa,0xe1,0xb4 };
    const uint8_t IV[] = { 0x6d,0xcc,0x99,0x63,0xf6,0x0e,0x61,0xbc,0x68,0x09,0xa6,0x68,0xe2,0xc6,0x0c,0x05 };
    const uint8_t PLAINTEXT[] = { 0xcc };
    const uint8_t CIPHERTEXT[] = { 0x76 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-67", "[CFB8][MCT][192][ENCRYPT][n67]") {
    const uint8_t KEY[] = { 0x0f,0xf8,0x04,0x65,0xf8,0xd9,0xcf,0x12,0x61,0xe2,0xb5,0x68,0x70,0x8f,0xb5,0x02,0x80,0x05,0x4e,0x33,0x50,0xe4,0x39,0xc2 };
    const uint8_t IV[] = { 0x58,0x40,0x53,0x4e,0x11,0x8a,0x31,0xf6,0xc1,0x94,0xba,0xfb,0xc7,0x1e,0xd8,0x76 };
    const uint8_t PLAINTEXT[] = { 0xba };
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

TEST_CASE("CFB8MCT192-ENCRYPT-68", "[CFB8][MCT][192][ENCRYPT][n68]") {
    const uint8_t KEY[] = { 0xf6,0x85,0x3e,0x35,0x50,0xb6,0x4b,0xc3,0xde,0x43,0x0d,0xde,0x01,0xa9,0x2a,0xc1,0x80,0x86,0x10,0x17,0xae,0xec,0x8f,0x3d };
    const uint8_t IV[] = { 0xbf,0xa1,0xb8,0xb6,0x71,0x26,0x9f,0xc3,0x00,0x83,0x5e,0x24,0xfe,0x08,0xb6,0xff };
    const uint8_t PLAINTEXT[] = { 0xd1 };
    const uint8_t CIPHERTEXT[] = { 0xc4 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-69", "[CFB8][MCT][192][ENCRYPT][n69]") {
    const uint8_t KEY[] = { 0xb9,0xbb,0xef,0x2e,0xf5,0x27,0x72,0x4c,0x54,0x60,0xf3,0xe7,0xd9,0xbf,0xc2,0x53,0x98,0x65,0xcf,0x17,0x21,0xd3,0xd4,0xf9 };
    const uint8_t IV[] = { 0x8a,0x23,0xfe,0x39,0xd8,0x16,0xe8,0x92,0x18,0xe3,0xdf,0x00,0x8f,0x3f,0x5b,0xc4 };
    const uint8_t PLAINTEXT[] = { 0x8f };
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

TEST_CASE("CFB8MCT192-ENCRYPT-70", "[CFB8][MCT][192][ENCRYPT][n70]") {
    const uint8_t KEY[] = { 0x46,0xff,0x74,0xe2,0x39,0x9e,0x1f,0x5b,0x96,0x93,0x2b,0xfa,0x29,0xa7,0x81,0x9f,0xd0,0x70,0x47,0xd4,0xf3,0x8b,0xdd,0x9f };
    const uint8_t IV[] = { 0xc2,0xf3,0xd8,0x1d,0xf0,0x18,0x43,0xcc,0x48,0x15,0x88,0xc3,0xd2,0x58,0x09,0x66 };
    const uint8_t PLAINTEXT[] = { 0x17 };
    const uint8_t CIPHERTEXT[] = { 0xf5 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-71", "[CFB8][MCT][192][ENCRYPT][n71]") {
    const uint8_t KEY[] = { 0xbd,0xa2,0x3c,0x38,0x47,0xf0,0x49,0x10,0x04,0x8d,0x8d,0x7c,0xe6,0x92,0x91,0xfd,0x13,0xec,0xbe,0x74,0xbe,0x73,0x4e,0x6a };
    const uint8_t IV[] = { 0x92,0x1e,0xa6,0x86,0xcf,0x35,0x10,0x62,0xc3,0x9c,0xf9,0xa0,0x4d,0xf8,0x93,0xf5 };
    const uint8_t PLAINTEXT[] = { 0x4b };
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

TEST_CASE("CFB8MCT192-ENCRYPT-72", "[CFB8][MCT][192][ENCRYPT][n72]") {
    const uint8_t KEY[] = { 0xc6,0x5c,0x94,0x07,0xb5,0x7c,0xef,0x68,0x59,0x7a,0xcd,0xf8,0x85,0xcf,0xc2,0x9b,0xb9,0xf8,0x1b,0xf5,0xb9,0x55,0x78,0xa7 };
    const uint8_t IV[] = { 0x5d,0xf7,0x40,0x84,0x63,0x5d,0x53,0x66,0xaa,0x14,0xa5,0x81,0x07,0x26,0x36,0xcd };
    const uint8_t PLAINTEXT[] = { 0x78 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-73", "[CFB8][MCT][192][ENCRYPT][n73]") {
    const uint8_t KEY[] = { 0xf6,0x8e,0x1f,0x48,0xf4,0x5b,0x9e,0xc4,0x23,0x2c,0x4b,0xb7,0x2d,0x0a,0x86,0xa8,0xa3,0xe2,0x33,0x42,0x01,0xa4,0x56,0x10 };
    const uint8_t IV[] = { 0x7a,0x56,0x86,0x4f,0xa8,0xc5,0x44,0x33,0x1a,0x1a,0x28,0xb7,0xb8,0xf1,0x2e,0xb7 };
    const uint8_t PLAINTEXT[] = { 0xac };
    const uint8_t CIPHERTEXT[] = { 0xc4 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-74", "[CFB8][MCT][192][ENCRYPT][n74]") {
    const uint8_t KEY[] = { 0x94,0x29,0x25,0x75,0x84,0xea,0x86,0xf1,0xa1,0x89,0xb8,0x39,0xbf,0x3f,0xfb,0x7f,0x26,0x6d,0xc1,0x28,0x2f,0x02,0x30,0xd4 };
    const uint8_t IV[] = { 0x82,0xa5,0xf3,0x8e,0x92,0x35,0x7d,0xd7,0x85,0x8f,0xf2,0x6a,0x2e,0xa6,0x66,0xc4 };
    const uint8_t PLAINTEXT[] = { 0x35 };
    const uint8_t CIPHERTEXT[] = { 0xc1 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-75", "[CFB8][MCT][192][ENCRYPT][n75]") {
    const uint8_t KEY[] = { 0x0e,0xac,0xf4,0x2f,0x7f,0xee,0xed,0xf4,0x45,0x19,0x14,0x23,0x1e,0x08,0x53,0x8b,0x33,0xe6,0xb1,0xde,0xf6,0x33,0xeb,0x15 };
    const uint8_t IV[] = { 0xe4,0x90,0xac,0x1a,0xa1,0x37,0xa8,0xf4,0x15,0x8b,0x70,0xf6,0xd9,0x31,0xdb,0xc1 };
    const uint8_t PLAINTEXT[] = { 0x05 };
    const uint8_t CIPHERTEXT[] = { 0xc1 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-76", "[CFB8][MCT][192][ENCRYPT][n76]") {
    const uint8_t KEY[] = { 0xc4,0x04,0x40,0xc4,0xb2,0x72,0x93,0x78,0xfe,0x97,0x9c,0x9b,0x50,0xde,0x2d,0xe4,0xc9,0xa3,0x90,0xad,0x60,0x1b,0x18,0xd4 };
    const uint8_t IV[] = { 0xbb,0x8e,0x88,0xb8,0x4e,0xd6,0x7e,0x6f,0xfa,0x45,0x21,0x73,0x96,0x28,0xf3,0xc1 };
    const uint8_t PLAINTEXT[] = { 0x8c };
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

TEST_CASE("CFB8MCT192-ENCRYPT-77", "[CFB8][MCT][192][ENCRYPT][n77]") {
    const uint8_t KEY[] = { 0x7e,0x8c,0x5a,0xd6,0x56,0xda,0x77,0xe4,0x55,0x10,0x87,0xd8,0xd5,0x39,0xf2,0x0c,0xb5,0x9b,0xb1,0x89,0x6d,0x58,0xeb,0x9b };
    const uint8_t IV[] = { 0xab,0x87,0x1b,0x43,0x85,0xe7,0xdf,0xe8,0x7c,0x38,0x21,0x24,0x0d,0x43,0xf3,0x4f };
    const uint8_t PLAINTEXT[] = { 0x9c };
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

TEST_CASE("CFB8MCT192-ENCRYPT-78", "[CFB8][MCT][192][ENCRYPT][n78]") {
    const uint8_t KEY[] = { 0x3e,0x58,0xa8,0x9b,0xb8,0xee,0xc8,0x46,0xe3,0xd8,0xfd,0xa6,0x8b,0xcb,0x4e,0xf0,0x66,0x34,0x7a,0x99,0xec,0x6e,0x2d,0x8c };
    const uint8_t IV[] = { 0xb6,0xc8,0x7a,0x7e,0x5e,0xf2,0xbc,0xfc,0xd3,0xaf,0xcb,0x10,0x81,0x36,0xc6,0x17 };
    const uint8_t PLAINTEXT[] = { 0xa2 };
    const uint8_t CIPHERTEXT[] = { 0x98 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-79", "[CFB8][MCT][192][ENCRYPT][n79]") {
    const uint8_t KEY[] = { 0x96,0xc0,0x34,0x8d,0x07,0xdd,0xc8,0x73,0x69,0x7f,0x90,0x13,0x19,0xad,0x11,0x1d,0x20,0x86,0x27,0xf2,0x35,0x5f,0x5b,0x14 };
    const uint8_t IV[] = { 0x8a,0xa7,0x6d,0xb5,0x92,0x66,0x5f,0xed,0x46,0xb2,0x5d,0x6b,0xd9,0x31,0x76,0x98 };
    const uint8_t PLAINTEXT[] = { 0x35 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-80", "[CFB8][MCT][192][ENCRYPT][n80]") {
    const uint8_t KEY[] = { 0xb4,0xc8,0x28,0x6a,0xdd,0xfe,0xb1,0x83,0x4a,0x2e,0xff,0x4b,0xb5,0xac,0xbd,0xc9,0x37,0x01,0x2a,0x22,0x9f,0x7a,0x3b,0xba };
    const uint8_t IV[] = { 0x23,0x51,0x6f,0x58,0xac,0x01,0xac,0xd4,0x17,0x87,0x0d,0xd0,0xaa,0x25,0x60,0xae };
    const uint8_t PLAINTEXT[] = { 0xf0 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-81", "[CFB8][MCT][192][ENCRYPT][n81]") {
    const uint8_t KEY[] = { 0x6c,0xfd,0x9b,0xb1,0x77,0xe2,0xf4,0xfd,0x36,0x54,0x9f,0xe0,0x94,0xb4,0x90,0xb9,0x9d,0x5a,0x29,0xd9,0x3b,0xa7,0x6d,0xcf };
    const uint8_t IV[] = { 0x7c,0x7a,0x60,0xab,0x21,0x18,0x2d,0x70,0xaa,0x5b,0x03,0xfb,0xa4,0xdd,0x56,0x75 };
    const uint8_t PLAINTEXT[] = { 0x7e };
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

TEST_CASE("CFB8MCT192-ENCRYPT-82", "[CFB8][MCT][192][ENCRYPT][n82]") {
    const uint8_t KEY[] = { 0xf2,0x87,0x7d,0x03,0xba,0xd9,0xca,0x37,0xd3,0xd6,0xb5,0x83,0xf3,0x6d,0x15,0x8c,0x4c,0x8c,0x53,0xd6,0x42,0x53,0xdb,0x6d };
    const uint8_t IV[] = { 0xe5,0x82,0x2a,0x63,0x67,0xd9,0x85,0x35,0xd1,0xd6,0x7a,0x0f,0x79,0xf4,0xb6,0xa2 };
    const uint8_t PLAINTEXT[] = { 0xca };
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

TEST_CASE("CFB8MCT192-ENCRYPT-83", "[CFB8][MCT][192][ENCRYPT][n83]") {
    const uint8_t KEY[] = { 0x4e,0x52,0xdd,0x13,0x27,0xf9,0xc2,0x18,0x9a,0xcb,0xe2,0x3a,0x2a,0x8c,0xb9,0xda,0x68,0x4f,0xfc,0x14,0x6c,0xe6,0x9f,0x22 };
    const uint8_t IV[] = { 0x49,0x1d,0x57,0xb9,0xd9,0xe1,0xac,0x56,0x24,0xc3,0xaf,0xc2,0x2e,0xb5,0x44,0x4f };
    const uint8_t PLAINTEXT[] = { 0x2f };
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

TEST_CASE("CFB8MCT192-ENCRYPT-84", "[CFB8][MCT][192][ENCRYPT][n84]") {
    const uint8_t KEY[] = { 0xb8,0xcb,0x9a,0x67,0x54,0x33,0x9d,0x58,0xd9,0x86,0x42,0x85,0xa1,0x67,0x13,0xee,0xe5,0x58,0xe3,0xfb,0x3b,0xff,0x6f,0x81 };
    const uint8_t IV[] = { 0x43,0x4d,0xa0,0xbf,0x8b,0xeb,0xaa,0x34,0x8d,0x17,0x1f,0xef,0x57,0x19,0xf0,0xa3 };
    const uint8_t PLAINTEXT[] = { 0x40 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-85", "[CFB8][MCT][192][ENCRYPT][n85]") {
    const uint8_t KEY[] = { 0x72,0xde,0x85,0xff,0x57,0x79,0x9d,0x41,0xec,0x75,0xd3,0x15,0x7f,0x5d,0x3d,0x16,0xde,0xc1,0x6d,0x89,0xa5,0xdd,0xdc,0xda };
    const uint8_t IV[] = { 0x35,0xf3,0x91,0x90,0xde,0x3a,0x2e,0xf8,0x3b,0x99,0x8e,0x72,0x9e,0x22,0xb3,0x5b };
    const uint8_t PLAINTEXT[] = { 0x19 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-86", "[CFB8][MCT][192][ENCRYPT][n86]") {
    const uint8_t KEY[] = { 0x2f,0xc5,0xc5,0xa7,0xc2,0x71,0x30,0x71,0x8d,0x85,0xd5,0x8f,0xfb,0xd1,0xce,0xb2,0x84,0x96,0xd6,0x4f,0xc6,0xa3,0x0e,0xf6 };
    const uint8_t IV[] = { 0x61,0xf0,0x06,0x9a,0x84,0x8c,0xf3,0xa4,0x5a,0x57,0xbb,0xc6,0x63,0x7e,0xd2,0x2c };
    const uint8_t PLAINTEXT[] = { 0x30 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-87", "[CFB8][MCT][192][ENCRYPT][n87]") {
    const uint8_t KEY[] = { 0x7a,0x7a,0xd1,0xeb,0x85,0x3d,0xe4,0x4b,0x01,0x1b,0x35,0xd0,0x5b,0x55,0x64,0x8f,0x8c,0xd5,0x12,0xbe,0xdf,0x36,0x7a,0x86 };
    const uint8_t IV[] = { 0x8c,0x9e,0xe0,0x5f,0xa0,0x84,0xaa,0x3d,0x08,0x43,0xc4,0xf1,0x19,0x95,0x74,0x70 };
    const uint8_t PLAINTEXT[] = { 0x3a };
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

TEST_CASE("CFB8MCT192-ENCRYPT-88", "[CFB8][MCT][192][ENCRYPT][n88]") {
    const uint8_t KEY[] = { 0x0d,0x97,0x37,0xb1,0x96,0x98,0x40,0x27,0x1e,0x0c,0xe5,0x4e,0x1d,0xb2,0x5b,0x3c,0x1a,0x69,0xac,0x4a,0x71,0x36,0x51,0xff };
    const uint8_t IV[] = { 0x1f,0x17,0xd0,0x9e,0x46,0xe7,0x3f,0xb3,0x96,0xbc,0xbe,0xf4,0xae,0x00,0x2b,0x79 };
    const uint8_t PLAINTEXT[] = { 0x6c };
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

TEST_CASE("CFB8MCT192-ENCRYPT-89", "[CFB8][MCT][192][ENCRYPT][n89]") {
    const uint8_t KEY[] = { 0x8c,0x56,0x8f,0x3a,0x55,0x24,0x52,0x07,0x11,0xa5,0x81,0xa7,0x6d,0x99,0x3b,0x53,0x47,0x33,0xe3,0x7c,0x44,0x93,0xf7,0x6b };
    const uint8_t IV[] = { 0x0f,0xa9,0x64,0xe9,0x70,0x2b,0x60,0x6f,0x5d,0x5a,0x4f,0x36,0x35,0xa5,0xa6,0x94 };
    const uint8_t PLAINTEXT[] = { 0x20 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-90", "[CFB8][MCT][192][ENCRYPT][n90]") {
    const uint8_t KEY[] = { 0x92,0xa2,0x40,0xaf,0xb2,0xb0,0x8a,0x4d,0x08,0x40,0x21,0xc3,0x7a,0x74,0x0d,0x2c,0x95,0xb5,0xf2,0x3e,0x07,0xbc,0xe9,0xdb };
    const uint8_t IV[] = { 0x19,0xe5,0xa0,0x64,0x17,0xed,0x36,0x7f,0xd2,0x86,0x11,0x42,0x43,0x2f,0x1e,0xb0 };
    const uint8_t PLAINTEXT[] = { 0x4a };
    const uint8_t CIPHERTEXT[] = { 0x3f };
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

TEST_CASE("CFB8MCT192-ENCRYPT-91", "[CFB8][MCT][192][ENCRYPT][n91]") {
    const uint8_t KEY[] = { 0x40,0x66,0xb2,0x11,0x72,0x89,0x28,0x36,0x4b,0x0d,0xf3,0xc9,0xe5,0x6d,0x3b,0x1f,0xbf,0x0d,0x2c,0xfd,0x52,0x49,0xa4,0xe4 };
    const uint8_t IV[] = { 0x43,0x4d,0xd2,0x0a,0x9f,0x19,0x36,0x33,0x2a,0xb8,0xde,0xc3,0x55,0xf5,0x4d,0x3f };
    const uint8_t PLAINTEXT[] = { 0x7b };
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

TEST_CASE("CFB8MCT192-ENCRYPT-92", "[CFB8][MCT][192][ENCRYPT][n92]") {
    const uint8_t KEY[] = { 0x3e,0x37,0x68,0xd8,0x22,0x3a,0x2c,0x7f,0xc8,0xd5,0x1d,0x5b,0x16,0xfb,0x6b,0xa9,0x7b,0x91,0xd6,0x3e,0x85,0xfd,0x36,0x19 };
    const uint8_t IV[] = { 0x83,0xd8,0xee,0x92,0xf3,0x96,0x50,0xb6,0xc4,0x9c,0xfa,0xc3,0xd7,0xb4,0x92,0xfd };
    const uint8_t PLAINTEXT[] = { 0x49 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-93", "[CFB8][MCT][192][ENCRYPT][n93]") {
    const uint8_t KEY[] = { 0x6f,0xa8,0xe0,0x1b,0x9c,0x1b,0x33,0xf6,0xed,0x6b,0xce,0x5d,0x45,0x57,0x84,0xef,0x5f,0x37,0xeb,0x76,0x36,0xfb,0x80,0x67 };
    const uint8_t IV[] = { 0x25,0xbe,0xd3,0x06,0x53,0xac,0xef,0x46,0x24,0xa6,0x3d,0x48,0xb3,0x06,0xb6,0x7e };
    const uint8_t PLAINTEXT[] = { 0x89 };
    const uint8_t CIPHERTEXT[] = { 0xd0 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-94", "[CFB8][MCT][192][ENCRYPT][n94]") {
    const uint8_t KEY[] = { 0xba,0x73,0x1f,0x8e,0x66,0x85,0x7d,0xa0,0xc8,0x7f,0xbb,0xc6,0x0e,0x8a,0x60,0x9f,0x0a,0xf8,0xdc,0x05,0x81,0xdb,0xfd,0xb7 };
    const uint8_t IV[] = { 0x25,0x14,0x75,0x9b,0x4b,0xdd,0xe4,0x70,0x55,0xcf,0x37,0x73,0xb7,0x20,0x7d,0xd0 };
    const uint8_t PLAINTEXT[] = { 0x56 };
    const uint8_t CIPHERTEXT[] = { 0xe8 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-95", "[CFB8][MCT][192][ENCRYPT][n95]") {
    const uint8_t KEY[] = { 0x96,0x36,0x67,0x47,0xdd,0xac,0x00,0xec,0xfc,0xec,0xde,0x8a,0x81,0x28,0x48,0x04,0x32,0x9d,0xdf,0x45,0x18,0xe3,0x08,0x5f };
    const uint8_t IV[] = { 0x34,0x93,0x65,0x4c,0x8f,0xa2,0x28,0x9b,0x38,0x65,0x03,0x40,0x99,0x38,0xf5,0xe8 };
    const uint8_t PLAINTEXT[] = { 0x4c };
    const uint8_t CIPHERTEXT[] = { 0xf9 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-96", "[CFB8][MCT][192][ENCRYPT][n96]") {
    const uint8_t KEY[] = { 0x0f,0xf8,0xae,0x84,0xec,0xab,0xa4,0x1b,0xeb,0x23,0x3f,0xcd,0x24,0xaa,0x1a,0xe6,0x12,0x90,0x07,0xd8,0xbd,0x29,0x0b,0xa6 };
    const uint8_t IV[] = { 0x17,0xcf,0xe1,0x47,0xa5,0x82,0x52,0xe2,0x20,0x0d,0xd8,0x9d,0xa5,0xca,0x03,0xf9 };
    const uint8_t PLAINTEXT[] = { 0xf7 };
    const uint8_t CIPHERTEXT[] = { 0x97 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-97", "[CFB8][MCT][192][ENCRYPT][n97]") {
    const uint8_t KEY[] = { 0x5a,0x92,0x34,0x07,0x8a,0x70,0x77,0xd8,0x7e,0xc6,0xee,0x05,0x3e,0x19,0xb8,0xb7,0xd2,0x45,0xb0,0x1d,0x4c,0x8f,0x75,0x31 };
    const uint8_t IV[] = { 0x95,0xe5,0xd1,0xc8,0x1a,0xb3,0xa2,0x51,0xc0,0xd5,0xb7,0xc5,0xf1,0xa6,0x7e,0x97 };
    const uint8_t PLAINTEXT[] = { 0xc3 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-98", "[CFB8][MCT][192][ENCRYPT][n98]") {
    const uint8_t KEY[] = { 0xce,0xf5,0x18,0xab,0xbc,0x98,0xa7,0x9e,0x35,0x46,0xa4,0xd6,0x3d,0x7c,0xac,0x88,0xf6,0x6e,0x5b,0x93,0xc9,0xd6,0x37,0x01 };
    const uint8_t IV[] = { 0x4b,0x80,0x4a,0xd3,0x03,0x65,0x14,0x3f,0x24,0x2b,0xeb,0x8e,0x85,0x59,0x42,0x30 };
    const uint8_t PLAINTEXT[] = { 0x46 };
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

TEST_CASE("CFB8MCT192-ENCRYPT-99", "[CFB8][MCT][192][ENCRYPT][n99]") {
    const uint8_t KEY[] = { 0x5d,0xd6,0x1a,0x29,0x25,0x1a,0x27,0x09,0x73,0x83,0x47,0x8b,0xe0,0x7d,0xee,0xd2,0x8d,0x7e,0xa1,0x95,0x67,0x68,0x8f,0x1e };
    const uint8_t IV[] = { 0x46,0xc5,0xe3,0x5d,0xdd,0x01,0x42,0x5a,0x7b,0x10,0xfa,0x06,0xae,0xbe,0xb8,0x1f };
    const uint8_t PLAINTEXT[] = { 0x97 };
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

TEST_CASE("CFB8MCT192-DECRYPT-0", "[CFB8][MCT][192][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0xd8,0x6b,0x0d,0xc7,0xa9,0x01,0x6a,0x8f,0xf5,0x78,0x40,0xa0,0x44,0x3e,0x11,0x08,0xc0,0xeb,0xe3,0x3f,0x52,0xd5,0x8b,0x5a };
    const uint8_t IV[] = { 0xd5,0xfc,0x3d,0x0c,0xdc,0xe1,0xe6,0x4d,0xa4,0x30,0x49,0x77,0x6e,0x32,0x59,0x3e };
    const uint8_t PLAINTEXT[] = { 0x11 };
    const uint8_t CIPHERTEXT[] = { 0x33 };
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

TEST_CASE("CFB8MCT192-DECRYPT-1", "[CFB8][MCT][192][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0x09,0x7c,0x0e,0x07,0x2f,0xd3,0xba,0x94,0x43,0x52,0xea,0xe0,0x09,0x83,0x02,0xcc,0x44,0x38,0x02,0xe3,0xa7,0x50,0x8f,0x4b };
    const uint8_t IV[] = { 0xb6,0x2a,0xaa,0x40,0x4d,0xbd,0x13,0xc4,0x84,0xd3,0xe1,0xdc,0xf5,0x85,0x04,0x11 };
    const uint8_t PLAINTEXT[] = { 0x29 };
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

TEST_CASE("CFB8MCT192-DECRYPT-2", "[CFB8][MCT][192][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0x15,0x30,0x5f,0x73,0x03,0xe5,0xfe,0x62,0xb5,0x68,0x21,0xf7,0xd6,0x3b,0xb1,0x87,0x5f,0x0d,0x30,0x0d,0xee,0x39,0x56,0x62 };
    const uint8_t IV[] = { 0xf6,0x3a,0xcb,0x17,0xdf,0xb8,0xb3,0x4b,0x1b,0x35,0x32,0xee,0x49,0x69,0xd9,0x29 };
    const uint8_t PLAINTEXT[] = { 0x32 };
    const uint8_t CIPHERTEXT[] = { 0xf6 };
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

TEST_CASE("CFB8MCT192-DECRYPT-3", "[CFB8][MCT][192][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0x6a,0xbf,0x0b,0x11,0xce,0x2e,0xb6,0xf1,0xfc,0x9d,0xa4,0x55,0x39,0x3d,0xd8,0x80,0xcb,0x47,0x74,0xc3,0x26,0x29,0x8d,0x50 };
    const uint8_t IV[] = { 0x49,0xf5,0x85,0xa2,0xef,0x06,0x69,0x07,0x94,0x4a,0x44,0xce,0xc8,0x10,0xdb,0x32 };
    const uint8_t PLAINTEXT[] = { 0xf1 };
    const uint8_t CIPHERTEXT[] = { 0x93 };
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

TEST_CASE("CFB8MCT192-DECRYPT-4", "[CFB8][MCT][192][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0x9c,0x76,0x0c,0xf9,0x03,0xef,0x3d,0xb9,0x02,0x23,0xb2,0xc7,0x9d,0xd5,0x5a,0x6e,0xef,0xed,0xaa,0xc2,0x13,0xae,0x39,0xa1 };
    const uint8_t IV[] = { 0xfe,0xbe,0x16,0x92,0xa4,0xe8,0x82,0xee,0x24,0xaa,0xde,0x01,0x35,0x87,0xb4,0xf1 };
    const uint8_t PLAINTEXT[] = { 0xa8 };
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

TEST_CASE("CFB8MCT192-DECRYPT-5", "[CFB8][MCT][192][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0xde,0x5e,0xa5,0xe7,0xea,0x39,0x20,0x61,0x45,0x8f,0xfc,0x6c,0x51,0x9c,0x1d,0xce,0x65,0xc7,0x9b,0xb8,0xba,0x11,0x27,0x09 };
    const uint8_t IV[] = { 0x47,0xac,0x4e,0xab,0xcc,0x49,0x47,0xa0,0x8a,0x2a,0x31,0x7a,0xa9,0xbf,0x1e,0xa8 };
    const uint8_t PLAINTEXT[] = { 0xe7 };
    const uint8_t CIPHERTEXT[] = { 0xd8 };
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

TEST_CASE("CFB8MCT192-DECRYPT-6", "[CFB8][MCT][192][DECRYPT][n6]") {
    const uint8_t KEY[] = { 0xa7,0x62,0xbc,0xba,0x0f,0xd6,0xd2,0xe3,0x21,0xea,0xa3,0x88,0x74,0x7c,0x8e,0xe2,0xa4,0xa0,0x78,0x7c,0x8a,0x1e,0x10,0xee };
    const uint8_t IV[] = { 0x64,0x65,0x5f,0xe4,0x25,0xe0,0x93,0x2c,0xc1,0x67,0xe3,0xc4,0x30,0x0f,0x37,0xe7 };
    const uint8_t PLAINTEXT[] = { 0xa8 };
    const uint8_t CIPHERTEXT[] = { 0x82 };
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

TEST_CASE("CFB8MCT192-DECRYPT-7", "[CFB8][MCT][192][DECRYPT][n7]") {
    const uint8_t KEY[] = { 0x24,0x14,0x51,0xea,0x1e,0x95,0x65,0xb1,0xf5,0xb9,0xfe,0x4c,0xe7,0xa9,0xc8,0x72,0x38,0x72,0x02,0xdb,0x30,0x6c,0x7a,0x46 };
    const uint8_t IV[] = { 0xd4,0x53,0x5d,0xc4,0x93,0xd5,0x46,0x90,0x9c,0xd2,0x7a,0xa7,0xba,0x72,0x6a,0xa8 };
    const uint8_t PLAINTEXT[] = { 0x3e };
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

TEST_CASE("CFB8MCT192-DECRYPT-8", "[CFB8][MCT][192][DECRYPT][n8]") {
    const uint8_t KEY[] = { 0x76,0x78,0xfc,0xc8,0x60,0x7b,0x86,0xa0,0x6a,0x2d,0x08,0xea,0x43,0x8f,0x8b,0x46,0xd4,0x3b,0x6a,0x31,0xbe,0xbc,0x67,0x78 };
    const uint8_t IV[] = { 0x9f,0x94,0xf6,0xa6,0xa4,0x26,0x43,0x34,0xec,0x49,0x68,0xea,0x8e,0xd0,0x1d,0x3e };
    const uint8_t PLAINTEXT[] = { 0x4a };
    const uint8_t CIPHERTEXT[] = { 0x11 };
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

TEST_CASE("CFB8MCT192-DECRYPT-9", "[CFB8][MCT][192][DECRYPT][n9]") {
    const uint8_t KEY[] = { 0xd4,0x64,0xf4,0xec,0x1c,0x30,0x14,0x1a,0x8d,0xf9,0xf9,0x76,0x81,0xee,0x4a,0xd5,0xc0,0xd0,0xc2,0x69,0xac,0x82,0x4d,0x32 };
    const uint8_t IV[] = { 0xe7,0xd4,0xf1,0x9c,0xc2,0x61,0xc1,0x93,0x14,0xeb,0xa8,0x58,0x12,0x3e,0x2a,0x4a };
    const uint8_t PLAINTEXT[] = { 0x80 };
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

TEST_CASE("CFB8MCT192-DECRYPT-10", "[CFB8][MCT][192][DECRYPT][n10]") {
    const uint8_t KEY[] = { 0x1c,0xe1,0x32,0x18,0x56,0x86,0x20,0xd2,0xcb,0xd7,0xf3,0x24,0xf3,0x4b,0xc5,0xb8,0xfa,0x5d,0x8e,0xe7,0x8d,0xb3,0x78,0xb2 };
    const uint8_t IV[] = { 0x46,0x2e,0x0a,0x52,0x72,0xa5,0x8f,0x6d,0x3a,0x8d,0x4c,0x8e,0x21,0x31,0x35,0x80 };
    const uint8_t PLAINTEXT[] = { 0x50 };
    const uint8_t CIPHERTEXT[] = { 0xc8 };
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

TEST_CASE("CFB8MCT192-DECRYPT-11", "[CFB8][MCT][192][DECRYPT][n11]") {
    const uint8_t KEY[] = { 0xab,0x22,0x75,0xf0,0xd7,0x8e,0x17,0xd8,0x4d,0x2c,0x2d,0xa5,0x65,0xcf,0xd6,0x34,0x81,0x42,0xe4,0xfa,0x42,0xb9,0xfb,0xe2 };
    const uint8_t IV[] = { 0x86,0xfb,0xde,0x81,0x96,0x84,0x13,0x8c,0x7b,0x1f,0x6a,0x1d,0xcf,0x0a,0x83,0x50 };
    const uint8_t PLAINTEXT[] = { 0x8b };
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

TEST_CASE("CFB8MCT192-DECRYPT-12", "[CFB8][MCT][192][DECRYPT][n12]") {
    const uint8_t KEY[] = { 0x66,0xde,0x43,0xae,0xe3,0x29,0x1c,0xc3,0x33,0x74,0x85,0xce,0xbc,0x1f,0xcc,0x20,0xef,0x8a,0xb7,0x58,0x12,0xb0,0xf7,0x69 };
    const uint8_t IV[] = { 0x7e,0x58,0xa8,0x6b,0xd9,0xd0,0x1a,0x14,0x6e,0xc8,0x53,0xa2,0x50,0x09,0x0c,0x8b };
    const uint8_t PLAINTEXT[] = { 0xc2 };
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

TEST_CASE("CFB8MCT192-DECRYPT-13", "[CFB8][MCT][192][DECRYPT][n13]") {
    const uint8_t KEY[] = { 0xce,0xb5,0x3b,0xe8,0x30,0x36,0xaf,0xb4,0x0d,0xfa,0x4b,0x1c,0x79,0x23,0xc4,0x88,0xee,0x8b,0x0f,0x74,0xbe,0xa3,0x8a,0xab };
    const uint8_t IV[] = { 0x3e,0x8e,0xce,0xd2,0xc5,0x3c,0x08,0xa8,0x01,0x01,0xb8,0x2c,0xac,0x13,0x7d,0xc2 };
    const uint8_t PLAINTEXT[] = { 0x07 };
    const uint8_t CIPHERTEXT[] = { 0x77 };
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

TEST_CASE("CFB8MCT192-DECRYPT-14", "[CFB8][MCT][192][DECRYPT][n14]") {
    const uint8_t KEY[] = { 0x89,0x20,0x47,0xed,0x8c,0x3a,0x36,0x52,0x95,0x31,0xbe,0x50,0x43,0x3b,0x58,0x45,0x67,0x79,0x91,0x42,0x42,0xb0,0x51,0xac };
    const uint8_t IV[] = { 0x98,0xcb,0xf5,0x4c,0x3a,0x18,0x9c,0xcd,0x89,0xf2,0x9e,0x36,0xfc,0x13,0xdb,0x07 };
    const uint8_t PLAINTEXT[] = { 0x62 };
    const uint8_t CIPHERTEXT[] = { 0xe6 };
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

TEST_CASE("CFB8MCT192-DECRYPT-15", "[CFB8][MCT][192][DECRYPT][n15]") {
    const uint8_t KEY[] = { 0x9d,0x73,0x53,0xcb,0x2c,0x81,0x9a,0xbb,0x32,0xce,0xa3,0xc6,0x62,0x31,0xcb,0x34,0x2d,0x84,0xe0,0x03,0x9d,0x09,0xe6,0xce };
    const uint8_t IV[] = { 0xa7,0xff,0x1d,0x96,0x21,0x0a,0x93,0x71,0x4a,0xfd,0x71,0x41,0xdf,0xb9,0xb7,0x62 };
    const uint8_t PLAINTEXT[] = { 0x2c };
    const uint8_t CIPHERTEXT[] = { 0xe9 };
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

TEST_CASE("CFB8MCT192-DECRYPT-16", "[CFB8][MCT][192][DECRYPT][n16]") {
    const uint8_t KEY[] = { 0x1a,0xb1,0x12,0xce,0x97,0x0f,0x19,0x33,0xfe,0xd0,0x98,0x66,0x51,0x4a,0xc6,0xf4,0xca,0x12,0xf0,0x29,0x33,0x07,0x79,0xe2 };
    const uint8_t IV[] = { 0xcc,0x1e,0x3b,0xa0,0x33,0x7b,0x0d,0xc0,0xe7,0x96,0x10,0x2a,0xae,0x0e,0x9f,0x2c };
    const uint8_t PLAINTEXT[] = { 0xa4 };
    const uint8_t CIPHERTEXT[] = { 0x88 };
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

TEST_CASE("CFB8MCT192-DECRYPT-17", "[CFB8][MCT][192][DECRYPT][n17]") {
    const uint8_t KEY[] = { 0x92,0x83,0x56,0xf6,0xfa,0xae,0xce,0x12,0x74,0x4d,0x7f,0xca,0x2e,0x6f,0xcc,0x38,0x08,0x38,0xfb,0xf6,0xd8,0x39,0x87,0x46 };
    const uint8_t IV[] = { 0x8a,0x9d,0xe7,0xac,0x7f,0x25,0x0a,0xcc,0xc2,0x2a,0x0b,0xdf,0xeb,0x3e,0xfe,0xa4 };
    const uint8_t PLAINTEXT[] = { 0xd4 };
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

TEST_CASE("CFB8MCT192-DECRYPT-18", "[CFB8][MCT][192][DECRYPT][n18]") {
    const uint8_t KEY[] = { 0x90,0xd6,0xc7,0x60,0x11,0xd8,0x25,0xae,0x76,0x35,0xac,0x32,0x1b,0x25,0x88,0xd9,0xad,0x40,0x87,0xba,0x88,0xd2,0xa0,0x92 };
    const uint8_t IV[] = { 0x02,0x78,0xd3,0xf8,0x35,0x4a,0x44,0xe1,0xa5,0x78,0x7c,0x4c,0x50,0xeb,0x27,0xd4 };
    const uint8_t PLAINTEXT[] = { 0xb6 };
    const uint8_t CIPHERTEXT[] = { 0xbc };
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

TEST_CASE("CFB8MCT192-DECRYPT-19", "[CFB8][MCT][192][DECRYPT][n19]") {
    const uint8_t KEY[] = { 0x59,0x4b,0x03,0xcb,0x28,0x99,0x0c,0x21,0x2d,0xbb,0xec,0xf2,0x77,0x55,0x82,0x9f,0xcd,0xa7,0xa0,0x45,0xf6,0x2d,0x08,0x24 };
    const uint8_t IV[] = { 0x5b,0x8e,0x40,0xc0,0x6c,0x70,0x0a,0x46,0x60,0xe7,0x27,0xff,0x7e,0xff,0xa8,0xb6 };
    const uint8_t PLAINTEXT[] = { 0x2d };
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

TEST_CASE("CFB8MCT192-DECRYPT-20", "[CFB8][MCT][192][DECRYPT][n20]") {
    const uint8_t KEY[] = { 0x82,0x37,0xdb,0xfb,0xeb,0x56,0xf0,0x5b,0x26,0x1a,0x4f,0x2d,0xca,0xb9,0x1d,0x22,0x0e,0xbf,0x75,0x85,0x19,0xb2,0xf4,0x09 };
    const uint8_t IV[] = { 0x0b,0xa1,0xa3,0xdf,0xbd,0xec,0x9f,0xbd,0xc3,0x18,0xd5,0xc0,0xef,0x9f,0xfc,0x2d };
    const uint8_t PLAINTEXT[] = { 0x35 };
    const uint8_t CIPHERTEXT[] = { 0x7a };
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

TEST_CASE("CFB8MCT192-DECRYPT-21", "[CFB8][MCT][192][DECRYPT][n21]") {
    const uint8_t KEY[] = { 0x09,0x08,0xf8,0x66,0x6e,0xb4,0xed,0xc7,0x56,0xe4,0x64,0x19,0xdf,0x2e,0x4a,0x21,0xb7,0xf3,0xb1,0x79,0x85,0xe4,0xde,0x3c };
    const uint8_t IV[] = { 0x70,0xfe,0x2b,0x34,0x15,0x97,0x57,0x03,0xb9,0x4c,0xc4,0xfc,0x9c,0x56,0x2a,0x35 };
    const uint8_t PLAINTEXT[] = { 0xd4 };
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

TEST_CASE("CFB8MCT192-DECRYPT-22", "[CFB8][MCT][192][DECRYPT][n22]") {
    const uint8_t KEY[] = { 0x5e,0x05,0xe6,0x18,0xd0,0xab,0x8f,0x72,0x76,0x7a,0x9d,0x42,0x36,0xe2,0xf4,0x55,0x6b,0x10,0x68,0xc8,0x75,0x60,0x27,0xe8 };
    const uint8_t IV[] = { 0x20,0x9e,0xf9,0x5b,0xe9,0xcc,0xbe,0x74,0xdc,0xe3,0xd9,0xb1,0xf0,0x84,0xf9,0xd4 };
    const uint8_t PLAINTEXT[] = { 0xf1 };
    const uint8_t CIPHERTEXT[] = { 0xb5 };
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

TEST_CASE("CFB8MCT192-DECRYPT-23", "[CFB8][MCT][192][DECRYPT][n23]") {
    const uint8_t KEY[] = { 0x68,0xbb,0x7d,0xac,0x0c,0xe8,0x87,0xc6,0xce,0xf7,0x6b,0x76,0x2c,0xeb,0xc8,0x24,0x25,0x89,0xca,0xd4,0x89,0xc8,0xbf,0x19 };
    const uint8_t IV[] = { 0xb8,0x8d,0xf6,0x34,0x1a,0x09,0x3c,0x71,0x4e,0x99,0xa2,0x1c,0xfc,0xa8,0x98,0xf1 };
    const uint8_t PLAINTEXT[] = { 0x53 };
    const uint8_t CIPHERTEXT[] = { 0xb4 };
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

TEST_CASE("CFB8MCT192-DECRYPT-24", "[CFB8][MCT][192][DECRYPT][n24]") {
    const uint8_t KEY[] = { 0xce,0x5f,0x24,0xa2,0xde,0xf4,0x68,0xf5,0x90,0xe1,0x94,0x7e,0xf0,0xd6,0x00,0x2c,0x0a,0x40,0xa1,0xfa,0xf6,0xeb,0xc0,0x4a };
    const uint8_t IV[] = { 0x5e,0x16,0xff,0x08,0xdc,0x3d,0xc8,0x08,0x2f,0xc9,0x6b,0x2e,0x7f,0x23,0x7f,0x53 };
    const uint8_t PLAINTEXT[] = { 0x94 };
    const uint8_t CIPHERTEXT[] = { 0x33 };
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

TEST_CASE("CFB8MCT192-DECRYPT-25", "[CFB8][MCT][192][DECRYPT][n25]") {
    const uint8_t KEY[] = { 0x55,0xa6,0x8d,0xae,0x65,0x27,0x80,0xc1,0x22,0x59,0x08,0xac,0x2f,0x4f,0x85,0x77,0xac,0xb3,0x6b,0x05,0xb7,0x57,0xeb,0xde };
    const uint8_t IV[] = { 0xb2,0xb8,0x9c,0xd2,0xdf,0x99,0x85,0x5b,0xa6,0xf3,0xca,0xff,0x41,0xbc,0x2b,0x94 };
    const uint8_t PLAINTEXT[] = { 0x8d };
    const uint8_t CIPHERTEXT[] = { 0x34 };
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

TEST_CASE("CFB8MCT192-DECRYPT-26", "[CFB8][MCT][192][DECRYPT][n26]") {
    const uint8_t KEY[] = { 0x20,0x09,0x5c,0x3a,0x3e,0x30,0x09,0xc2,0xad,0x15,0x43,0x43,0x7e,0xf8,0xf0,0x9c,0x65,0xd0,0x6b,0x31,0x8c,0x7e,0xfb,0x53 };
    const uint8_t IV[] = { 0x8f,0x4c,0x4b,0xef,0x51,0xb7,0x75,0xeb,0xc9,0x63,0x00,0x34,0x3b,0x29,0x10,0x8d };
    const uint8_t PLAINTEXT[] = { 0x98 };
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

TEST_CASE("CFB8MCT192-DECRYPT-27", "[CFB8][MCT][192][DECRYPT][n27]") {
    const uint8_t KEY[] = { 0xd5,0xeb,0x18,0x99,0x06,0x39,0x12,0xc2,0xc3,0x70,0x61,0xe9,0xb0,0x05,0x29,0x8b,0x97,0x85,0xdf,0xd3,0x66,0xf3,0x8d,0xcb };
    const uint8_t IV[] = { 0x6e,0x65,0x22,0xaa,0xce,0xfd,0xd9,0x17,0xf2,0x55,0xb4,0xe2,0xea,0x8d,0x76,0x98 };
    const uint8_t PLAINTEXT[] = { 0xa7 };
    const uint8_t CIPHERTEXT[] = { 0x00 };
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

TEST_CASE("CFB8MCT192-DECRYPT-28", "[CFB8][MCT][192][DECRYPT][n28]") {
    const uint8_t KEY[] = { 0x24,0xdd,0xda,0x0b,0xd0,0x12,0x1b,0x0c,0x5b,0x98,0x4f,0xe4,0xf9,0xef,0x3f,0x66,0x10,0x21,0xf1,0x8f,0x2b,0xa4,0x8b,0x6c };
    const uint8_t IV[] = { 0x98,0xe8,0x2e,0x0d,0x49,0xea,0x16,0xed,0x87,0xa4,0x2e,0x5c,0x4d,0x57,0x06,0xa7 };
    const uint8_t PLAINTEXT[] = { 0x00 };
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

TEST_CASE("CFB8MCT192-DECRYPT-29", "[CFB8][MCT][192][DECRYPT][n29]") {
    const uint8_t KEY[] = { 0xad,0x3f,0x5d,0x66,0x74,0xe3,0x9e,0xaa,0xff,0x8c,0x3b,0x66,0x06,0xb4,0xa3,0x31,0xb6,0x01,0x32,0x14,0xad,0x60,0x8a,0x6c };
    const uint8_t IV[] = { 0xa4,0x14,0x74,0x82,0xff,0x5b,0x9c,0x57,0xa6,0x20,0xc3,0x9b,0x86,0xc4,0x01,0x00 };
    const uint8_t PLAINTEXT[] = { 0x1c };
    const uint8_t CIPHERTEXT[] = { 0xa6 };
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

TEST_CASE("CFB8MCT192-DECRYPT-30", "[CFB8][MCT][192][DECRYPT][n30]") {
    const uint8_t KEY[] = { 0x2d,0x6f,0x7a,0x71,0xd0,0x44,0x36,0x41,0x04,0xa4,0x07,0xa0,0x70,0x2d,0x5f,0x64,0x31,0xed,0x3d,0x8d,0xa6,0x42,0xd0,0x70 };
    const uint8_t IV[] = { 0xfb,0x28,0x3c,0xc6,0x76,0x99,0xfc,0x55,0x87,0xec,0x0f,0x99,0x0b,0x22,0x5a,0x1c };
    const uint8_t PLAINTEXT[] = { 0xdf };
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

TEST_CASE("CFB8MCT192-DECRYPT-31", "[CFB8][MCT][192][DECRYPT][n31]") {
    const uint8_t KEY[] = { 0xca,0x2b,0xd8,0xe4,0x72,0x9f,0xb8,0x1c,0xe2,0x8b,0x51,0x21,0xe7,0x67,0xa7,0xd9,0x74,0x72,0xbe,0x5e,0x9a,0x42,0xd6,0xaf };
    const uint8_t IV[] = { 0xe6,0x2f,0x56,0x81,0x97,0x4a,0xf8,0xbd,0x45,0x9f,0x83,0xd3,0x3c,0x00,0x06,0xdf };
    const uint8_t PLAINTEXT[] = { 0x26 };
    const uint8_t CIPHERTEXT[] = { 0x5d };
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

TEST_CASE("CFB8MCT192-DECRYPT-32", "[CFB8][MCT][192][DECRYPT][n32]") {
    const uint8_t KEY[] = { 0x4e,0xa9,0x73,0xb6,0x01,0xa4,0x9e,0xdb,0xf0,0xd9,0x67,0x0e,0x67,0x94,0x75,0x07,0xfe,0xc9,0x25,0x42,0x56,0x16,0x30,0x89 };
    const uint8_t IV[] = { 0x12,0x52,0x36,0x2f,0x80,0xf3,0xd2,0xde,0x8a,0xbb,0x9b,0x1c,0xcc,0x54,0xe6,0x26 };
    const uint8_t PLAINTEXT[] = { 0x9c };
    const uint8_t CIPHERTEXT[] = { 0xc7 };
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

TEST_CASE("CFB8MCT192-DECRYPT-33", "[CFB8][MCT][192][DECRYPT][n33]") {
    const uint8_t KEY[] = { 0xec,0x84,0xd8,0x15,0x62,0x5e,0x96,0x7f,0x9c,0x91,0xdf,0xfe,0x58,0xda,0xb2,0x44,0x2e,0x7f,0x83,0xf8,0x2d,0x7b,0xda,0x15 };
    const uint8_t IV[] = { 0x6c,0x48,0xb8,0xf0,0x3f,0x4e,0xc7,0x43,0xd0,0xb6,0xa6,0xba,0x7b,0x6d,0xea,0x9c };
    const uint8_t PLAINTEXT[] = { 0xc0 };
    const uint8_t CIPHERTEXT[] = { 0xa4 };
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

TEST_CASE("CFB8MCT192-DECRYPT-34", "[CFB8][MCT][192][DECRYPT][n34]") {
    const uint8_t KEY[] = { 0x2a,0x4b,0xde,0x1c,0x07,0x72,0x94,0x42,0x79,0x2e,0xdf,0xd8,0xf1,0x91,0xb6,0x22,0x63,0x8c,0x9c,0x11,0x38,0x6b,0x18,0xd5 };
    const uint8_t IV[] = { 0xe5,0xbf,0x00,0x26,0xa9,0x4b,0x04,0x66,0x4d,0xf3,0x1f,0xe9,0x15,0x10,0xc2,0xc0 };
    const uint8_t PLAINTEXT[] = { 0x9e };
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

TEST_CASE("CFB8MCT192-DECRYPT-35", "[CFB8][MCT][192][DECRYPT][n35]") {
    const uint8_t KEY[] = { 0xf3,0x3b,0xb7,0x03,0x5f,0xd4,0x3a,0x24,0xbc,0xf2,0x6c,0x39,0xac,0x9a,0x00,0x93,0x3e,0x41,0x15,0xf1,0x4b,0xb5,0x70,0x4b };
    const uint8_t IV[] = { 0xc5,0xdc,0xb3,0xe1,0x5d,0x0b,0xb6,0xb1,0x5d,0xcd,0x89,0xe0,0x73,0xde,0x68,0x9e };
    const uint8_t PLAINTEXT[] = { 0xb3 };
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

TEST_CASE("CFB8MCT192-DECRYPT-36", "[CFB8][MCT][192][DECRYPT][n36]") {
    const uint8_t KEY[] = { 0x4c,0xb4,0x32,0x03,0x32,0x41,0xdd,0x64,0x0f,0x5a,0x1c,0x2c,0x9c,0x09,0xf2,0xc5,0x37,0x0a,0x3c,0xf0,0xee,0x87,0x4f,0xf8 };
    const uint8_t IV[] = { 0xb3,0xa8,0x70,0x15,0x30,0x93,0xf2,0x56,0x09,0x4b,0x29,0x01,0xa5,0x32,0x3f,0xb3 };
    const uint8_t PLAINTEXT[] = { 0xa3 };
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

TEST_CASE("CFB8MCT192-DECRYPT-37", "[CFB8][MCT][192][DECRYPT][n37]") {
    const uint8_t KEY[] = { 0x7c,0x98,0xc2,0x4c,0xa4,0x97,0x68,0x0f,0x47,0xf1,0x93,0x57,0x98,0xd9,0x4f,0x6a,0xbe,0x20,0x03,0x6a,0xd9,0x2f,0x47,0x5b };
    const uint8_t IV[] = { 0x48,0xab,0x8f,0x7b,0x04,0xd0,0xbd,0xaf,0x89,0x2a,0x3f,0x9a,0x37,0xa8,0x08,0xa3 };
    const uint8_t PLAINTEXT[] = { 0xcb };
    const uint8_t CIPHERTEXT[] = { 0x6b };
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

TEST_CASE("CFB8MCT192-DECRYPT-38", "[CFB8][MCT][192][DECRYPT][n38]") {
    const uint8_t KEY[] = { 0x6a,0xde,0x44,0xaf,0x84,0x24,0xb5,0x7e,0xe3,0x87,0x68,0x0e,0xf0,0x72,0x8c,0x7d,0x95,0x88,0x59,0x7c,0x14,0xb1,0x19,0x90 };
    const uint8_t IV[] = { 0xa4,0x76,0xfb,0x59,0x68,0xab,0xc3,0x17,0x2b,0xa8,0x5a,0x16,0xcd,0x9e,0x5e,0xcb };
    const uint8_t PLAINTEXT[] = { 0x69 };
    const uint8_t CIPHERTEXT[] = { 0x71 };
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

TEST_CASE("CFB8MCT192-DECRYPT-39", "[CFB8][MCT][192][DECRYPT][n39]") {
    const uint8_t KEY[] = { 0x5f,0xca,0xf5,0xe3,0xfc,0x6d,0xc5,0xb7,0x52,0xa4,0xe7,0x55,0x06,0x0a,0xd9,0xc6,0xa9,0x92,0x09,0xb5,0x73,0x21,0x4d,0xf9 };
    const uint8_t IV[] = { 0xb1,0x23,0x8f,0x5b,0xf6,0x78,0x55,0xbb,0x3c,0x1a,0x50,0xc9,0x67,0x90,0x54,0x69 };
    const uint8_t PLAINTEXT[] = { 0x3a };
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

TEST_CASE("CFB8MCT192-DECRYPT-40", "[CFB8][MCT][192][DECRYPT][n40]") {
    const uint8_t KEY[] = { 0x46,0x5a,0x9a,0x6f,0xbf,0x4f,0x0b,0xcf,0x52,0x2e,0xf3,0xcf,0xe7,0x55,0x8b,0x74,0x1d,0x71,0x72,0xa3,0x7a,0x0a,0x41,0xc3 };
    const uint8_t IV[] = { 0x00,0x8a,0x14,0x9a,0xe1,0x5f,0x52,0xb2,0xb4,0xe3,0x7b,0x16,0x09,0x2b,0x0c,0x3a };
    const uint8_t PLAINTEXT[] = { 0x89 };
    const uint8_t CIPHERTEXT[] = { 0x78 };
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

TEST_CASE("CFB8MCT192-DECRYPT-41", "[CFB8][MCT][192][DECRYPT][n41]") {
    const uint8_t KEY[] = { 0x36,0xb5,0x78,0x55,0x7e,0x1b,0x2c,0xd5,0x88,0x65,0xff,0x59,0xa1,0x52,0x98,0x5f,0x9e,0x46,0xc9,0x99,0xee,0x2a,0x1b,0x4a };
    const uint8_t IV[] = { 0xda,0x4b,0x0c,0x96,0x46,0x07,0x13,0x2b,0x83,0x37,0xbb,0x3a,0x94,0x20,0x5a,0x89 };
    const uint8_t PLAINTEXT[] = { 0xc8 };
    const uint8_t CIPHERTEXT[] = { 0x1a };
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

TEST_CASE("CFB8MCT192-DECRYPT-42", "[CFB8][MCT][192][DECRYPT][n42]") {
    const uint8_t KEY[] = { 0xcb,0x8f,0xc5,0xe8,0x01,0xc5,0x13,0x1a,0xe7,0x4b,0x3f,0xbb,0x1d,0x06,0x55,0xf3,0x2c,0x7e,0x53,0x2a,0x2c,0x02,0xb8,0x82 };
    const uint8_t IV[] = { 0x6f,0x2e,0xc0,0xe2,0xbc,0x54,0xcd,0xac,0xb2,0x38,0x9a,0xb3,0xc2,0x28,0xa3,0xc8 };
    const uint8_t PLAINTEXT[] = { 0x64 };
    const uint8_t CIPHERTEXT[] = { 0xcf };
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

TEST_CASE("CFB8MCT192-DECRYPT-43", "[CFB8][MCT][192][DECRYPT][n43]") {
    const uint8_t KEY[] = { 0xe7,0x0f,0x21,0xac,0xbc,0xe5,0x8e,0x35,0x05,0xb1,0xce,0xfa,0xb1,0x72,0x00,0x48,0xc1,0x59,0xb8,0xa9,0xa2,0xce,0xb8,0xe6 };
    const uint8_t IV[] = { 0xe2,0xfa,0xf1,0x41,0xac,0x74,0x55,0xbb,0xed,0x27,0xeb,0x83,0x8e,0xcc,0x00,0x64 };
    const uint8_t PLAINTEXT[] = { 0x08 };
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

TEST_CASE("CFB8MCT192-DECRYPT-44", "[CFB8][MCT][192][DECRYPT][n44]") {
    const uint8_t KEY[] = { 0x1f,0x44,0xb5,0xd9,0xea,0xcc,0xf7,0xad,0x30,0x86,0xb7,0x22,0x49,0x2e,0xff,0x61,0xd0,0x4d,0x22,0x6a,0x33,0x65,0x54,0xee };
    const uint8_t IV[] = { 0x35,0x37,0x79,0xd8,0xf8,0x5c,0xff,0x29,0x11,0x14,0x9a,0xc3,0x91,0xab,0xec,0x08 };
    const uint8_t PLAINTEXT[] = { 0x04 };
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

TEST_CASE("CFB8MCT192-DECRYPT-45", "[CFB8][MCT][192][DECRYPT][n45]") {
    const uint8_t KEY[] = { 0x5a,0xc1,0xef,0x5b,0x33,0x8f,0x74,0x86,0x5f,0x21,0x5a,0xc4,0x0a,0xcb,0xf4,0xe8,0x02,0xc6,0xc6,0xf9,0x1b,0x50,0x88,0xea };
    const uint8_t IV[] = { 0x6f,0xa7,0xed,0xe6,0x43,0xe5,0x0b,0x89,0xd2,0x8b,0xe4,0x93,0x28,0x35,0xdc,0x04 };
    const uint8_t PLAINTEXT[] = { 0xaa };
    const uint8_t CIPHERTEXT[] = { 0x2b };
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

TEST_CASE("CFB8MCT192-DECRYPT-46", "[CFB8][MCT][192][DECRYPT][n46]") {
    const uint8_t KEY[] = { 0x4e,0x5a,0x35,0x74,0xdd,0xed,0x16,0x64,0x83,0x37,0x01,0x6a,0xc1,0x64,0x19,0x25,0xcf,0x39,0x8b,0xeb,0x71,0x80,0x4c,0x40 };
    const uint8_t IV[] = { 0xdc,0x16,0x5b,0xae,0xcb,0xaf,0xed,0xcd,0xcd,0xff,0x4d,0x12,0x6a,0xd0,0xc4,0xaa };
    const uint8_t PLAINTEXT[] = { 0x5c };
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

TEST_CASE("CFB8MCT192-DECRYPT-47", "[CFB8][MCT][192][DECRYPT][n47]") {
    const uint8_t KEY[] = { 0x2a,0x90,0xac,0x72,0x5f,0x5d,0x0d,0x7b,0xb9,0x61,0x71,0x07,0xad,0xc2,0xb3,0xc2,0x42,0x00,0x4b,0x48,0x2c,0x0b,0xa2,0x1c };
    const uint8_t IV[] = { 0x3a,0x56,0x70,0x6d,0x6c,0xa6,0xaa,0xe7,0x8d,0x39,0xc0,0xa3,0x5d,0x8b,0xee,0x5c };
    const uint8_t PLAINTEXT[] = { 0xd3 };
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

TEST_CASE("CFB8MCT192-DECRYPT-48", "[CFB8][MCT][192][DECRYPT][n48]") {
    const uint8_t KEY[] = { 0x21,0x7b,0x7e,0x00,0x3b,0x21,0x04,0xe7,0x34,0x0e,0x0f,0x25,0xdd,0x29,0x12,0x20,0xe9,0xf5,0x4b,0x3b,0xc8,0x0a,0x47,0xcf };
    const uint8_t IV[] = { 0x8d,0x6f,0x7e,0x22,0x70,0xeb,0xa1,0xe2,0xab,0xf5,0x00,0x73,0xe4,0x01,0xe5,0xd3 };
    const uint8_t PLAINTEXT[] = { 0xc5 };
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

TEST_CASE("CFB8MCT192-DECRYPT-49", "[CFB8][MCT][192][DECRYPT][n49]") {
    const uint8_t KEY[] = { 0xec,0xfe,0x8a,0x4f,0x79,0xfa,0xb8,0x7f,0x79,0x96,0xbc,0x89,0x44,0xfa,0x85,0x39,0xe4,0xc4,0xc4,0x23,0x82,0x73,0x87,0x0a };
    const uint8_t IV[] = { 0x4d,0x98,0xb3,0xac,0x99,0xd3,0x97,0x19,0x0d,0x31,0x8f,0x18,0x4a,0x79,0xc0,0xc5 };
    const uint8_t PLAINTEXT[] = { 0x28 };
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

TEST_CASE("CFB8MCT192-DECRYPT-50", "[CFB8][MCT][192][DECRYPT][n50]") {
    const uint8_t KEY[] = { 0xea,0x75,0xca,0x9e,0x45,0x78,0x36,0x67,0x4f,0xe9,0xd6,0x24,0x83,0xcc,0xbd,0xad,0x53,0x47,0x3b,0x44,0x55,0xa7,0xde,0x22 };
    const uint8_t IV[] = { 0x36,0x7f,0x6a,0xad,0xc7,0x36,0x38,0x94,0xb7,0x83,0xff,0x67,0xd7,0xd4,0x59,0x28 };
    const uint8_t PLAINTEXT[] = { 0xa8 };
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

TEST_CASE("CFB8MCT192-DECRYPT-51", "[CFB8][MCT][192][DECRYPT][n51]") {
    const uint8_t KEY[] = { 0x7d,0x6d,0x9f,0x5c,0x0c,0xbd,0x05,0xc2,0x8d,0xd2,0xd9,0xda,0xfc,0xfd,0x09,0x35,0x8d,0x43,0xae,0x60,0xb9,0x31,0x08,0x8a };
    const uint8_t IV[] = { 0xc2,0x3b,0x0f,0xfe,0x7f,0x31,0xb4,0x98,0xde,0x04,0x95,0x24,0xec,0x96,0xd6,0xa8 };
    const uint8_t PLAINTEXT[] = { 0xe7 };
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

TEST_CASE("CFB8MCT192-DECRYPT-52", "[CFB8][MCT][192][DECRYPT][n52]") {
    const uint8_t KEY[] = { 0x63,0xe0,0x43,0x1a,0x57,0x17,0xa5,0xe3,0x0f,0x59,0xec,0x7e,0x30,0x8e,0x93,0xc9,0xe8,0x01,0x7c,0x47,0xa6,0x3f,0xaf,0x6d };
    const uint8_t IV[] = { 0x82,0x8b,0x35,0xa4,0xcc,0x73,0x9a,0xfc,0x65,0x42,0xd2,0x27,0x1f,0x0e,0xa7,0xe7 };
    const uint8_t PLAINTEXT[] = { 0x5e };
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

TEST_CASE("CFB8MCT192-DECRYPT-53", "[CFB8][MCT][192][DECRYPT][n53]") {
    const uint8_t KEY[] = { 0x6b,0x21,0x6f,0xb0,0x8b,0x37,0x98,0x7e,0x41,0x2b,0x0e,0xbb,0xc4,0x1a,0xcc,0x38,0x7d,0x39,0x4a,0x06,0xee,0xc7,0xaf,0x33 };
    const uint8_t IV[] = { 0x4e,0x72,0xe2,0xc5,0xf4,0x94,0x5f,0xf1,0x95,0x38,0x36,0x41,0x48,0xf8,0x00,0x5e };
    const uint8_t PLAINTEXT[] = { 0xaf };
    const uint8_t CIPHERTEXT[] = { 0x9d };
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

TEST_CASE("CFB8MCT192-DECRYPT-54", "[CFB8][MCT][192][DECRYPT][n54]") {
    const uint8_t KEY[] = { 0xa5,0x2a,0x7c,0x83,0x4f,0x32,0x5e,0xbb,0x49,0x3d,0x3d,0x1b,0xfa,0x2a,0x0c,0xf8,0x1a,0x1d,0x50,0x4f,0x9d,0x67,0x3e,0x9c };
    const uint8_t IV[] = { 0x08,0x16,0x33,0xa0,0x3e,0x30,0xc0,0xc0,0x67,0x24,0x1a,0x49,0x73,0xa0,0x91,0xaf };
    const uint8_t PLAINTEXT[] = { 0x43 };
    const uint8_t CIPHERTEXT[] = { 0xc5 };
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

TEST_CASE("CFB8MCT192-DECRYPT-55", "[CFB8][MCT][192][DECRYPT][n55]") {
    const uint8_t KEY[] = { 0xf5,0xe0,0xbc,0xa6,0xca,0x5c,0x04,0x09,0x94,0x95,0xff,0x92,0xfb,0xf8,0xd3,0xf6,0x12,0x1a,0x15,0x64,0xb5,0xae,0xb6,0xdf };
    const uint8_t IV[] = { 0xdd,0xa8,0xc2,0x89,0x01,0xd2,0xdf,0x0e,0x08,0x07,0x45,0x2b,0x28,0xc9,0x88,0x43 };
    const uint8_t PLAINTEXT[] = { 0xee };
    const uint8_t CIPHERTEXT[] = { 0xb2 };
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

TEST_CASE("CFB8MCT192-DECRYPT-56", "[CFB8][MCT][192][DECRYPT][n56]") {
    const uint8_t KEY[] = { 0xfb,0xd4,0x6f,0xa9,0x65,0xf4,0x3c,0xc2,0x80,0xd3,0xf5,0xac,0xc0,0xe4,0x19,0x62,0xe5,0xfc,0x58,0x37,0x4e,0xb3,0x6f,0x31 };
    const uint8_t IV[] = { 0x14,0x46,0x0a,0x3e,0x3b,0x1c,0xca,0x94,0xf7,0xe6,0x4d,0x53,0xfb,0x1d,0xd9,0xee };
    const uint8_t PLAINTEXT[] = { 0x6b };
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

TEST_CASE("CFB8MCT192-DECRYPT-57", "[CFB8][MCT][192][DECRYPT][n57]") {
    const uint8_t KEY[] = { 0x2c,0x3d,0x7c,0x6b,0xb3,0xd4,0x14,0xd1,0x15,0x00,0xe9,0x40,0xec,0x39,0x13,0x16,0x15,0xdd,0x3a,0x6d,0xa7,0x75,0xe4,0x5a };
    const uint8_t IV[] = { 0x95,0xd3,0x1c,0xec,0x2c,0xdd,0x0a,0x74,0xf0,0x21,0x62,0x5a,0xe9,0xc6,0x8b,0x6b };
    const uint8_t PLAINTEXT[] = { 0xd3 };
    const uint8_t CIPHERTEXT[] = { 0x13 };
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

TEST_CASE("CFB8MCT192-DECRYPT-58", "[CFB8][MCT][192][DECRYPT][n58]") {
    const uint8_t KEY[] = { 0x32,0x98,0x53,0xff,0x9b,0x66,0x0b,0xaa,0x93,0xf7,0xe0,0xf1,0xb1,0x0d,0x0e,0x0b,0x4e,0x33,0x67,0xd6,0xb6,0x96,0xbf,0x89 };
    const uint8_t IV[] = { 0x86,0xf7,0x09,0xb1,0x5d,0x34,0x1d,0x1d,0x5b,0xee,0x5d,0xbb,0x11,0xe3,0x5b,0xd3 };
    const uint8_t PLAINTEXT[] = { 0x5c };
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

TEST_CASE("CFB8MCT192-DECRYPT-59", "[CFB8][MCT][192][DECRYPT][n59]") {
    const uint8_t KEY[] = { 0xf4,0x78,0xff,0xeb,0xdb,0x52,0xc4,0x20,0xc4,0x5d,0x5b,0x92,0x2c,0xd2,0x6d,0x5d,0xd0,0xb8,0x5b,0xb3,0x4f,0x61,0x5b,0xd5 };
    const uint8_t IV[] = { 0x57,0xaa,0xbb,0x63,0x9d,0xdf,0x63,0x56,0x9e,0x8b,0x3c,0x65,0xf9,0xf7,0xe4,0x5c };
    const uint8_t PLAINTEXT[] = { 0x3f };
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

TEST_CASE("CFB8MCT192-DECRYPT-60", "[CFB8][MCT][192][DECRYPT][n60]") {
    const uint8_t KEY[] = { 0xc2,0xe3,0xea,0xe8,0x6b,0x09,0x19,0x2f,0x78,0x39,0xa1,0xc1,0x35,0xa8,0x62,0x14,0x3a,0xd8,0x26,0x1f,0xc4,0x41,0x7a,0xea };
    const uint8_t IV[] = { 0xbc,0x64,0xfa,0x53,0x19,0x7a,0x0f,0x49,0xea,0x60,0x7d,0xac,0x8b,0x20,0x21,0x3f };
    const uint8_t PLAINTEXT[] = { 0x4e };
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

TEST_CASE("CFB8MCT192-DECRYPT-61", "[CFB8][MCT][192][DECRYPT][n61]") {
    const uint8_t KEY[] = { 0x73,0xd0,0x2e,0xff,0xd1,0x0a,0xe3,0xa2,0x01,0x96,0x98,0x0a,0x9d,0x87,0x6b,0xcd,0x9b,0x25,0x8f,0x0c,0x43,0x64,0xa8,0xa4 };
    const uint8_t IV[] = { 0x79,0xaf,0x39,0xcb,0xa8,0x2f,0x09,0xd9,0xa1,0xfd,0xa9,0x13,0x87,0x25,0xd2,0x4e };
    const uint8_t PLAINTEXT[] = { 0xf5 };
    const uint8_t CIPHERTEXT[] = { 0x8d };
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

TEST_CASE("CFB8MCT192-DECRYPT-62", "[CFB8][MCT][192][DECRYPT][n62]") {
    const uint8_t KEY[] = { 0x1d,0x7d,0x5d,0x9f,0x51,0x5e,0x0b,0x4b,0xcc,0x0e,0xf4,0xd9,0xa3,0x7f,0x86,0xe9,0x8d,0xf5,0xa4,0x75,0xa7,0x91,0x4f,0x51 };
    const uint8_t IV[] = { 0xcd,0x98,0x6c,0xd3,0x3e,0xf8,0xed,0x24,0x16,0xd0,0x2b,0x79,0xe4,0xf5,0xe7,0xf5 };
    const uint8_t PLAINTEXT[] = { 0xa7 };
    const uint8_t CIPHERTEXT[] = { 0xe9 };
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

TEST_CASE("CFB8MCT192-DECRYPT-63", "[CFB8][MCT][192][DECRYPT][n63]") {
    const uint8_t KEY[] = { 0x89,0x35,0xab,0xd2,0x59,0xa6,0xf9,0x5c,0xe6,0x8a,0x5f,0xd1,0xbf,0x72,0x96,0x87,0x66,0x5d,0x59,0x5f,0x80,0x90,0x94,0xf6 };
    const uint8_t IV[] = { 0x2a,0x84,0xab,0x08,0x1c,0x0d,0x10,0x6e,0xeb,0xa8,0xfd,0x2a,0x27,0x01,0xdb,0xa7 };
    const uint8_t PLAINTEXT[] = { 0x4a };
    const uint8_t CIPHERTEXT[] = { 0x17 };
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

TEST_CASE("CFB8MCT192-DECRYPT-64", "[CFB8][MCT][192][DECRYPT][n64]") {
    const uint8_t KEY[] = { 0xbe,0x93,0x4b,0xa4,0x52,0x97,0x74,0xc2,0x99,0xc7,0xac,0xaa,0x3a,0x2d,0x7f,0x77,0x95,0x11,0x15,0xb4,0x03,0x93,0x0c,0xbc };
    const uint8_t IV[] = { 0x7f,0x4d,0xf3,0x7b,0x85,0x5f,0xe9,0xf0,0xf3,0x4c,0x4c,0xeb,0x83,0x03,0x98,0x4a };
    const uint8_t PLAINTEXT[] = { 0x0b };
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

TEST_CASE("CFB8MCT192-DECRYPT-65", "[CFB8][MCT][192][DECRYPT][n65]") {
    const uint8_t KEY[] = { 0xf6,0x97,0xc1,0xfc,0x57,0x54,0x82,0xf6,0x10,0xfc,0x15,0xc1,0x3a,0x4f,0x61,0xb1,0xa2,0xcc,0xaa,0x24,0xa6,0xe8,0xe3,0xb7 };
    const uint8_t IV[] = { 0x89,0x3b,0xb9,0x6b,0x00,0x62,0x1e,0xc6,0x37,0xdd,0xbf,0x90,0xa5,0x7b,0xef,0x0b };
    const uint8_t PLAINTEXT[] = { 0x36 };
    const uint8_t CIPHERTEXT[] = { 0x34 };
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

TEST_CASE("CFB8MCT192-DECRYPT-66", "[CFB8][MCT][192][DECRYPT][n66]") {
    const uint8_t KEY[] = { 0x44,0xbf,0x4f,0x03,0xee,0x9d,0xd3,0x24,0x2b,0x6c,0x28,0xa0,0x55,0xf4,0xe0,0x07,0xda,0x76,0xad,0x09,0x55,0xf3,0x59,0x81 };
    const uint8_t IV[] = { 0x3b,0x90,0x3d,0x61,0x6f,0xbb,0x81,0xb6,0x78,0xba,0x07,0x2d,0xf3,0x1b,0xba,0x36 };
    const uint8_t PLAINTEXT[] = { 0x92 };
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

TEST_CASE("CFB8MCT192-DECRYPT-67", "[CFB8][MCT][192][DECRYPT][n67]") {
    const uint8_t KEY[] = { 0xdb,0xfc,0x64,0xf1,0x03,0x11,0x16,0xee,0xcc,0x1d,0xe9,0x93,0xc3,0x47,0x5b,0x51,0xde,0x2a,0xf8,0x92,0xc8,0x9f,0x44,0x13 };
    const uint8_t IV[] = { 0xe7,0x71,0xc1,0x33,0x96,0xb3,0xbb,0x56,0x04,0x5c,0x55,0x9b,0x9d,0x6c,0x1d,0x92 };
    const uint8_t PLAINTEXT[] = { 0x60 };
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

TEST_CASE("CFB8MCT192-DECRYPT-68", "[CFB8][MCT][192][DECRYPT][n68]") {
    const uint8_t KEY[] = { 0x31,0x2e,0xbf,0xa0,0xcd,0x6d,0x30,0xb1,0x3b,0x59,0x0f,0xd8,0x12,0x28,0xce,0xe7,0x6a,0x58,0xcf,0x2d,0x4f,0x9d,0x3e,0x73 };
    const uint8_t IV[] = { 0xf7,0x44,0xe6,0x4b,0xd1,0x6f,0x95,0xb6,0xb4,0x72,0x37,0xbf,0x87,0x02,0x7a,0x60 };
    const uint8_t PLAINTEXT[] = { 0x4a };
    const uint8_t CIPHERTEXT[] = { 0x5f };
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

TEST_CASE("CFB8MCT192-DECRYPT-69", "[CFB8][MCT][192][DECRYPT][n69]") {
    const uint8_t KEY[] = { 0xee,0x63,0x14,0x7c,0xab,0x29,0xb9,0xdd,0xba,0x92,0xf6,0x64,0x33,0xd2,0x97,0x94,0xb0,0x75,0xe0,0x9b,0x5b,0x37,0xae,0x39 };
    const uint8_t IV[] = { 0x81,0xcb,0xf9,0xbc,0x21,0xfa,0x59,0x73,0xda,0x2d,0x2f,0xb6,0x14,0xaa,0x90,0x4a };
    const uint8_t PLAINTEXT[] = { 0x6a };
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

TEST_CASE("CFB8MCT192-DECRYPT-70", "[CFB8][MCT][192][DECRYPT][n70]") {
    const uint8_t KEY[] = { 0xda,0xa4,0x33,0x59,0x34,0x0d,0x6b,0xd5,0xfe,0xdc,0xd4,0xd7,0x6d,0xb5,0x08,0x1d,0x75,0x40,0xe7,0x5e,0x47,0xd3,0x10,0x53 };
    const uint8_t IV[] = { 0x44,0x4e,0x22,0xb3,0x5e,0x67,0x9f,0x89,0xc5,0x35,0x07,0xc5,0x1c,0xe4,0xbe,0x6a };
    const uint8_t PLAINTEXT[] = { 0x58 };
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

TEST_CASE("CFB8MCT192-DECRYPT-71", "[CFB8][MCT][192][DECRYPT][n71]") {
    const uint8_t KEY[] = { 0x17,0xe8,0x40,0x3c,0xc3,0xfa,0xbc,0xb6,0xa9,0x7c,0x43,0xf9,0x52,0x6a,0xee,0xff,0xb0,0x94,0xe9,0x62,0xf0,0xde,0x05,0x0b };
    const uint8_t IV[] = { 0x57,0xa0,0x97,0x2e,0x3f,0xdf,0xe6,0xe2,0xc5,0xd4,0x0e,0x3c,0xb7,0x0d,0x15,0x58 };
    const uint8_t PLAINTEXT[] = { 0x40 };
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

TEST_CASE("CFB8MCT192-DECRYPT-72", "[CFB8][MCT][192][DECRYPT][n72]") {
    const uint8_t KEY[] = { 0xd1,0x4b,0x6d,0xca,0xaf,0x44,0x76,0xd8,0xf7,0x54,0xea,0xa5,0xec,0x75,0xc1,0x57,0x76,0xe7,0x89,0xd6,0x28,0x51,0x86,0x4b };
    const uint8_t IV[] = { 0x5e,0x28,0xa9,0x5c,0xbe,0x1f,0x2f,0xa8,0xc6,0x73,0x60,0xb4,0xd8,0x8f,0x83,0x40 };
    const uint8_t PLAINTEXT[] = { 0x4f };
    const uint8_t CIPHERTEXT[] = { 0x6e };
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

TEST_CASE("CFB8MCT192-DECRYPT-73", "[CFB8][MCT][192][DECRYPT][n73]") {
    const uint8_t KEY[] = { 0xf0,0x67,0xf0,0x43,0x00,0x36,0x62,0x6f,0x88,0x10,0xba,0x43,0xf3,0x18,0x87,0xad,0x76,0x62,0x75,0x3d,0x87,0xa9,0x7f,0x04 };
    const uint8_t IV[] = { 0x7f,0x44,0x50,0xe6,0x1f,0x6d,0x46,0xfa,0x00,0x85,0xfc,0xeb,0xaf,0xf8,0xf9,0x4f };
    const uint8_t PLAINTEXT[] = { 0xcd };
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

TEST_CASE("CFB8MCT192-DECRYPT-74", "[CFB8][MCT][192][DECRYPT][n74]") {
    const uint8_t KEY[] = { 0x65,0x7c,0x55,0xc7,0x21,0x09,0x40,0x26,0x9f,0xd7,0xe7,0x2d,0x30,0x04,0x43,0xc0,0x3a,0x32,0x6f,0x41,0xdc,0x89,0x3b,0xc9 };
    const uint8_t IV[] = { 0x17,0xc7,0x5d,0x6e,0xc3,0x1c,0xc4,0x6d,0x4c,0x50,0x1a,0x7c,0x5b,0x20,0x44,0xcd };
    const uint8_t PLAINTEXT[] = { 0x8d };
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

TEST_CASE("CFB8MCT192-DECRYPT-75", "[CFB8][MCT][192][DECRYPT][n75]") {
    const uint8_t KEY[] = { 0x50,0x9d,0x69,0x01,0x51,0x2d,0xa7,0x05,0x57,0xc8,0xf1,0x4c,0x59,0x7d,0x27,0x09,0x0d,0xf5,0x44,0xb2,0x47,0x0c,0x87,0x44 };
    const uint8_t IV[] = { 0xc8,0x1f,0x16,0x61,0x69,0x79,0x64,0xc9,0x37,0xc7,0x2b,0xf3,0x9b,0x85,0xbc,0x8d };
    const uint8_t PLAINTEXT[] = { 0xf8 };
    const uint8_t CIPHERTEXT[] = { 0x23 };
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

TEST_CASE("CFB8MCT192-DECRYPT-76", "[CFB8][MCT][192][DECRYPT][n76]") {
    const uint8_t KEY[] = { 0xb9,0xa7,0xda,0xe6,0x0b,0x81,0xda,0xc9,0x0a,0xde,0x81,0x91,0x35,0x85,0xcc,0xfc,0x69,0xdd,0xf4,0xf9,0x42,0x67,0xb3,0xbc };
    const uint8_t IV[] = { 0x5d,0x16,0x70,0xdd,0x6c,0xf8,0xeb,0xf5,0x64,0x28,0xb0,0x4b,0x05,0x6b,0x34,0xf8 };
    const uint8_t PLAINTEXT[] = { 0xea };
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

TEST_CASE("CFB8MCT192-DECRYPT-77", "[CFB8][MCT][192][DECRYPT][n77]") {
    const uint8_t KEY[] = { 0x38,0x64,0x9e,0xa1,0x4e,0x12,0x7b,0x51,0xfc,0x86,0xba,0x85,0xc4,0xb2,0xd6,0x65,0xb4,0x1d,0x20,0x58,0xde,0xf5,0xf4,0x56 };
    const uint8_t IV[] = { 0xf6,0x58,0x3b,0x14,0xf1,0x37,0x1a,0x99,0xdd,0xc0,0xd4,0xa1,0x9c,0x92,0x47,0xea };
    const uint8_t PLAINTEXT[] = { 0x8e };
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

TEST_CASE("CFB8MCT192-DECRYPT-78", "[CFB8][MCT][192][DECRYPT][n78]") {
    const uint8_t KEY[] = { 0xc1,0x45,0x3c,0x60,0x73,0x7a,0x18,0xcf,0xe7,0xd9,0x75,0x9e,0x89,0xca,0x81,0xb7,0x74,0x54,0x83,0xf9,0x53,0xee,0x50,0xd8 };
    const uint8_t IV[] = { 0x1b,0x5f,0xcf,0x1b,0x4d,0x78,0x57,0xd2,0xc0,0x49,0xa3,0xa1,0x8d,0x1b,0xa4,0x8e };
    const uint8_t PLAINTEXT[] = { 0xfb };
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

TEST_CASE("CFB8MCT192-DECRYPT-79", "[CFB8][MCT][192][DECRYPT][n79]") {
    const uint8_t KEY[] = { 0x1e,0x27,0x57,0x32,0x51,0x0b,0x5c,0xdf,0x48,0xc4,0xf5,0x4d,0x50,0xe9,0x4c,0x3a,0x08,0x75,0xc4,0x0e,0x98,0x91,0x3c,0x23 };
    const uint8_t IV[] = { 0xaf,0x1d,0x80,0xd3,0xd9,0x23,0xcd,0x8d,0x7c,0x21,0x47,0xf7,0xcb,0x7f,0x6c,0xfb };
    const uint8_t PLAINTEXT[] = { 0x0b };
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

TEST_CASE("CFB8MCT192-DECRYPT-80", "[CFB8][MCT][192][DECRYPT][n80]") {
    const uint8_t KEY[] = { 0xa9,0x19,0x0e,0x81,0xd3,0xe5,0x17,0x37,0xf2,0xa7,0x70,0x1f,0x9a,0x82,0xae,0x83,0xfe,0xc0,0x63,0x6e,0x5b,0xc3,0x01,0x28 };
    const uint8_t IV[] = { 0xba,0x63,0x85,0x52,0xca,0x6b,0xe2,0xb9,0xf6,0xb5,0xa7,0x60,0xc3,0x52,0x3d,0x0b };
    const uint8_t PLAINTEXT[] = { 0x93 };
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

TEST_CASE("CFB8MCT192-DECRYPT-81", "[CFB8][MCT][192][DECRYPT][n81]") {
    const uint8_t KEY[] = { 0x7a,0xff,0xeb,0xc6,0x2d,0x60,0xbb,0xa4,0x98,0xe5,0x43,0xcd,0x7a,0xa3,0x1c,0xbc,0x01,0xc9,0x16,0x22,0xe9,0x11,0xde,0xbb };
    const uint8_t IV[] = { 0x6a,0x42,0x33,0xd2,0xe0,0x21,0xb2,0x3f,0xff,0x09,0x75,0x4c,0xb2,0xd2,0xdf,0x93 };
    const uint8_t PLAINTEXT[] = { 0x2c };
    const uint8_t CIPHERTEXT[] = { 0x93 };
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

TEST_CASE("CFB8MCT192-DECRYPT-82", "[CFB8][MCT][192][DECRYPT][n82]") {
    const uint8_t KEY[] = { 0x8a,0x71,0x54,0x58,0xc3,0xf7,0x6c,0x4c,0x78,0x89,0xd7,0xa4,0xbc,0xef,0xa1,0x9c,0x8a,0x09,0xb3,0x46,0xb4,0x18,0x24,0x97 };
    const uint8_t IV[] = { 0xe0,0x6c,0x94,0x69,0xc6,0x4c,0xbd,0x20,0x8b,0xc0,0xa5,0x64,0x5d,0x09,0xfa,0x2c };
    const uint8_t PLAINTEXT[] = { 0x27 };
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

TEST_CASE("CFB8MCT192-DECRYPT-83", "[CFB8][MCT][192][DECRYPT][n83]") {
    const uint8_t KEY[] = { 0x46,0xe0,0x6b,0x48,0xc5,0x08,0x46,0xe6,0x94,0x54,0xa8,0xc4,0x23,0xdd,0xd0,0x3f,0x73,0xc2,0x21,0x64,0x9e,0x66,0x27,0xb0 };
    const uint8_t IV[] = { 0xec,0xdd,0x7f,0x60,0x9f,0x32,0x71,0xa3,0xf9,0xcb,0x92,0x22,0x2a,0x7e,0x03,0x27 };
    const uint8_t PLAINTEXT[] = { 0x33 };
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

TEST_CASE("CFB8MCT192-DECRYPT-84", "[CFB8][MCT][192][DECRYPT][n84]") {
    const uint8_t KEY[] = { 0x5b,0x21,0x0a,0x54,0xd4,0x0e,0x8e,0x1a,0xe6,0xd1,0xf7,0x53,0x3f,0xa9,0xdc,0x65,0x9a,0xc0,0xd0,0xbc,0x57,0x1e,0x21,0x83 };
    const uint8_t IV[] = { 0x72,0x85,0x5f,0x97,0x1c,0x74,0x0c,0x5a,0xe9,0x02,0xf1,0xd8,0xc9,0x78,0x06,0x33 };
    const uint8_t PLAINTEXT[] = { 0x17 };
    const uint8_t CIPHERTEXT[] = { 0xfc };
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

TEST_CASE("CFB8MCT192-DECRYPT-85", "[CFB8][MCT][192][DECRYPT][n85]") {
    const uint8_t KEY[] = { 0xad,0xe0,0x9f,0x82,0xde,0xf1,0xe9,0x7c,0xf1,0x4b,0xe7,0x47,0xbf,0x14,0x88,0x50,0x21,0x98,0x4b,0x95,0xa3,0x4e,0xa4,0x94 };
    const uint8_t IV[] = { 0x17,0x9a,0x10,0x14,0x80,0xbd,0x54,0x35,0xbb,0x58,0x9b,0x29,0xf4,0x50,0x85,0x17 };
    const uint8_t PLAINTEXT[] = { 0xc3 };
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

TEST_CASE("CFB8MCT192-DECRYPT-86", "[CFB8][MCT][192][DECRYPT][n86]") {
    const uint8_t KEY[] = { 0x53,0xc6,0x11,0x67,0x63,0x35,0x7c,0x78,0xd9,0xc5,0x40,0xf4,0xff,0x4c,0xef,0xa1,0xcf,0x31,0x97,0x21,0x91,0xbe,0xf0,0x57 };
    const uint8_t IV[] = { 0x28,0x8e,0xa7,0xb3,0x40,0x58,0x67,0xf1,0xee,0xa9,0xdc,0xb4,0x32,0xf0,0x54,0xc3 };
    const uint8_t PLAINTEXT[] = { 0x19 };
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

TEST_CASE("CFB8MCT192-DECRYPT-87", "[CFB8][MCT][192][DECRYPT][n87]") {
    const uint8_t KEY[] = { 0x15,0x67,0xc3,0x51,0xcd,0x82,0xc5,0x2f,0x4b,0x57,0xd5,0xc8,0x66,0xe2,0xc8,0x5b,0x27,0xae,0xb5,0x19,0xde,0x1d,0xc2,0x4e };
    const uint8_t IV[] = { 0x92,0x92,0x95,0x3c,0x99,0xae,0x27,0xfa,0xe8,0x9f,0x22,0x38,0x4f,0xa3,0x32,0x19 };
    const uint8_t PLAINTEXT[] = { 0x23 };
    const uint8_t CIPHERTEXT[] = { 0x57 };
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

TEST_CASE("CFB8MCT192-DECRYPT-88", "[CFB8][MCT][192][DECRYPT][n88]") {
    const uint8_t KEY[] = { 0xdd,0x5a,0xf5,0xa6,0x28,0x8a,0x75,0x62,0x94,0xb0,0x27,0x71,0xbb,0x11,0x28,0x5c,0x05,0x4e,0xbe,0x9b,0xf8,0xd2,0xc9,0x6d };
    const uint8_t IV[] = { 0xdf,0xe7,0xf2,0xb9,0xdd,0xf3,0xe0,0x07,0x22,0xe0,0x0b,0x82,0x26,0xcf,0x0b,0x23 };
    const uint8_t PLAINTEXT[] = { 0x0d };
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

TEST_CASE("CFB8MCT192-DECRYPT-89", "[CFB8][MCT][192][DECRYPT][n89]") {
    const uint8_t KEY[] = { 0x91,0x51,0x03,0x29,0x61,0xa3,0xa5,0xd3,0x4d,0x98,0xfe,0x2e,0x8a,0x70,0xb7,0x09,0xdb,0xaf,0x7e,0x32,0x05,0x73,0x91,0x60 };
    const uint8_t IV[] = { 0xd9,0x28,0xd9,0x5f,0x31,0x61,0x9f,0x55,0xde,0xe1,0xc0,0xa9,0xfd,0xa1,0x58,0x0d };
    const uint8_t PLAINTEXT[] = { 0x10 };
    const uint8_t CIPHERTEXT[] = { 0xb1 };
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

TEST_CASE("CFB8MCT192-DECRYPT-90", "[CFB8][MCT][192][DECRYPT][n90]") {
    const uint8_t KEY[] = { 0x64,0xfe,0x12,0x76,0x21,0x28,0xc6,0x04,0x2d,0x0d,0x5d,0x5b,0xb6,0xfe,0x82,0xd5,0x2c,0x6f,0x9b,0xf8,0x6c,0x79,0x15,0x70 };
    const uint8_t IV[] = { 0x60,0x95,0xa3,0x75,0x3c,0x8e,0x35,0xdc,0xf7,0xc0,0xe5,0xca,0x69,0x0a,0x84,0x10 };
    const uint8_t PLAINTEXT[] = { 0x24 };
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

TEST_CASE("CFB8MCT192-DECRYPT-91", "[CFB8][MCT][192][DECRYPT][n91]") {
    const uint8_t KEY[] = { 0x38,0xaf,0x09,0x3a,0xa2,0x6c,0x76,0x08,0x5b,0x20,0x95,0xab,0xa5,0xe5,0x10,0x1b,0x3c,0x5d,0xb8,0x5f,0x3b,0x2e,0x98,0x54 };
    const uint8_t IV[] = { 0x76,0x2d,0xc8,0xf0,0x13,0x1b,0x92,0xce,0x10,0x32,0x23,0xa7,0x57,0x57,0x8d,0x24 };
    const uint8_t PLAINTEXT[] = { 0xb2 };
    const uint8_t CIPHERTEXT[] = { 0x0c };
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

TEST_CASE("CFB8MCT192-DECRYPT-92", "[CFB8][MCT][192][DECRYPT][n92]") {
    const uint8_t KEY[] = { 0x15,0x31,0x9d,0x29,0x61,0xbd,0x65,0xe9,0x71,0xfc,0x0a,0x32,0xcd,0x0f,0xec,0x32,0xb0,0x63,0x36,0xc2,0x24,0x33,0x48,0xe6 };
    const uint8_t IV[] = { 0x2a,0xdc,0x9f,0x99,0x68,0xea,0xfc,0x29,0x8c,0x3e,0x8e,0x9d,0x1f,0x1d,0xd0,0xb2 };
    const uint8_t PLAINTEXT[] = { 0xfe };
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

TEST_CASE("CFB8MCT192-DECRYPT-93", "[CFB8][MCT][192][DECRYPT][n93]") {
    const uint8_t KEY[] = { 0x8d,0x12,0x7f,0xd8,0x40,0xaf,0xf7,0x60,0x8c,0x7c,0xbc,0x40,0x79,0x40,0x4a,0x86,0x64,0xc0,0x90,0xe6,0x8a,0xb4,0xea,0x18 };
    const uint8_t IV[] = { 0xfd,0x80,0xb6,0x72,0xb4,0x4f,0xa6,0xb4,0xd4,0xa3,0xa6,0x24,0xae,0x87,0xa2,0xfe };
    const uint8_t PLAINTEXT[] = { 0x15 };
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

TEST_CASE("CFB8MCT192-DECRYPT-94", "[CFB8][MCT][192][DECRYPT][n94]") {
    const uint8_t KEY[] = { 0x32,0x2d,0x66,0x4b,0xf2,0xfa,0x9d,0xeb,0x93,0xa3,0xf8,0x53,0xcf,0x12,0xd8,0xdd,0x61,0xf1,0x81,0x76,0x8d,0xf6,0x5d,0x0d };
    const uint8_t IV[] = { 0x1f,0xdf,0x44,0x13,0xb6,0x52,0x92,0x5b,0x05,0x31,0x11,0x90,0x07,0x42,0xb7,0x15 };
    const uint8_t PLAINTEXT[] = { 0x19 };
    const uint8_t CIPHERTEXT[] = { 0x8b };
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

TEST_CASE("CFB8MCT192-DECRYPT-95", "[CFB8][MCT][192][DECRYPT][n95]") {
    const uint8_t KEY[] = { 0xd8,0xe6,0xd8,0xf4,0x97,0x4d,0xf5,0x79,0xb5,0xc7,0x13,0xb5,0x92,0x89,0xa3,0x67,0xfe,0xc1,0x7f,0x30,0x56,0x63,0xfe,0x14 };
    const uint8_t IV[] = { 0x26,0x64,0xeb,0xe6,0x5d,0x9b,0x7b,0xba,0x9f,0x30,0xfe,0x46,0xdb,0x95,0xa3,0x19 };
    const uint8_t PLAINTEXT[] = { 0xca };
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

TEST_CASE("CFB8MCT192-DECRYPT-96", "[CFB8][MCT][192][DECRYPT][n96]") {
    const uint8_t KEY[] = { 0x17,0xcd,0x2e,0x46,0xa2,0x7d,0x9d,0x0f,0x91,0x60,0xa0,0x1e,0xda,0x70,0x59,0x8b,0x1d,0x2d,0x70,0x5d,0xc6,0x29,0xf3,0xde };
    const uint8_t IV[] = { 0x24,0xa7,0xb3,0xab,0x48,0xf9,0xfa,0xec,0xe3,0xec,0x0f,0x6d,0x90,0x4a,0x0d,0xca };
    const uint8_t PLAINTEXT[] = { 0xeb };
    const uint8_t CIPHERTEXT[] = { 0x76 };
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

TEST_CASE("CFB8MCT192-DECRYPT-97", "[CFB8][MCT][192][DECRYPT][n97]") {
    const uint8_t KEY[] = { 0x59,0x84,0xb9,0xe9,0x36,0xbc,0xfa,0x34,0x8f,0xd2,0x56,0x22,0x2d,0x7c,0xa6,0x17,0x4f,0x8a,0x40,0xc6,0x88,0x8c,0x07,0x35 };
    const uint8_t IV[] = { 0x1e,0xb2,0xf6,0x3c,0xf7,0x0c,0xff,0x9c,0x52,0xa7,0x30,0x9b,0x4e,0xa5,0xf4,0xeb };
    const uint8_t PLAINTEXT[] = { 0xf6 };
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

TEST_CASE("CFB8MCT192-DECRYPT-98", "[CFB8][MCT][192][DECRYPT][n98]") {
    const uint8_t KEY[] = { 0xd6,0x46,0xea,0xc4,0xdf,0x35,0x69,0x54,0x1b,0x4f,0xd9,0x0f,0xd4,0xd7,0x4c,0x37,0xfb,0x98,0xf6,0x71,0x49,0xc2,0x77,0xc3 };
    const uint8_t IV[] = { 0x94,0x9d,0x8f,0x2d,0xf9,0xab,0xea,0x20,0xb4,0x12,0xb6,0xb7,0xc1,0x4e,0x70,0xf6 };
    const uint8_t PLAINTEXT[] = { 0xf3 };
    const uint8_t CIPHERTEXT[] = { 0x60 };
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

TEST_CASE("CFB8MCT192-DECRYPT-99", "[CFB8][MCT][192][DECRYPT][n99]") {
    const uint8_t KEY[] = { 0x6a,0x04,0x4e,0x72,0xe4,0x4c,0x0e,0x09,0x33,0x20,0x71,0x17,0xbb,0xd1,0xa3,0x92,0xe6,0x8e,0x49,0xbf,0x31,0xe3,0xb2,0x30 };
    const uint8_t IV[] = { 0x28,0x6f,0xa8,0x18,0x6f,0x06,0xef,0xa5,0x1d,0x16,0xbf,0xce,0x78,0x21,0xc5,0xf3 };
    const uint8_t PLAINTEXT[] = { 0x4b };
    const uint8_t CIPHERTEXT[] = { 0x5d };
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

