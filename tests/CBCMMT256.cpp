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

TEST_CASE("CBCMMT256-ENCRYPT-0", "[CBC][MMT][256][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0x6e,0xd7,0x6d,0x2d,0x97,0xc6,0x9f,0xd1,0x33,0x95,0x89,0x52,0x39,0x31,0xf2,0xa6,0xcf,0xf5,0x54,0xb1,0x5f,0x73,0x8f,0x21,0xec,0x72,0xdd,0x97,0xa7,0x33,0x09,0x07 };
    const uint8_t IV[] = { 0x85,0x1e,0x87,0x64,0x77,0x6e,0x67,0x96,0xaa,0xb7,0x22,0xdb,0xb6,0x44,0xac,0xe8 };
    const uint8_t PLAINTEXT[] = { 0x62,0x82,0xb8,0xc0,0x5c,0x5c,0x15,0x30,0xb9,0x7d,0x48,0x16,0xca,0x43,0x47,0x62 };
    const uint8_t CIPHERTEXT[] = { 0x6a,0xcc,0x04,0x14,0x2e,0x10,0x0a,0x65,0xf5,0x1b,0x97,0xad,0xf5,0x17,0x2c,0x41 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cbc(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CBCMMT256-ENCRYPT-1", "[CBC][MMT][256][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0xdc,0xe2,0x6c,0x6b,0x4c,0xfb,0x28,0x65,0x10,0xda,0x4e,0xec,0xd2,0xcf,0xfe,0x6c,0xdf,0x43,0x0f,0x33,0xdb,0x9b,0x5f,0x77,0xb4,0x60,0x67,0x9b,0xd4,0x9d,0x13,0xae };
    const uint8_t IV[] = { 0xfd,0xea,0xa1,0x34,0xc8,0xd7,0x37,0x9d,0x45,0x71,0x75,0xfd,0x1a,0x57,0xd3,0xfc };
    const uint8_t PLAINTEXT[] = { 0x50,0xe9,0xee,0xe1,0xac,0x52,0x80,0x09,0xe8,0xcb,0xcd,0x35,0x69,0x75,0x88,0x1f,0x95,0x72,0x54,0xb1,0x3f,0x91,0xd7,0xc6,0x66,0x2d,0x10,0x31,0x20,0x52,0xeb,0x00 };
    const uint8_t CIPHERTEXT[] = { 0x2f,0xa0,0xdf,0x72,0x2a,0x9f,0xd3,0xb6,0x4c,0xb1,0x8f,0xb2,0xb3,0xdb,0x55,0xff,0x22,0x67,0x42,0x27,0x57,0x28,0x94,0x13,0xf8,0xf6,0x57,0x50,0x74,0x12,0xa6,0x4c };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cbc(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CBCMMT256-ENCRYPT-2", "[CBC][MMT][256][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0xfe,0x89,0x01,0xfe,0xcd,0x3c,0xcd,0x2e,0xc5,0xfd,0xc7,0xc7,0xa0,0xb5,0x05,0x19,0xc2,0x45,0xb4,0x2d,0x61,0x1a,0x5e,0xf9,0xe9,0x02,0x68,0xd5,0x9f,0x3e,0xdf,0x33 };
    const uint8_t IV[] = { 0xbd,0x41,0x6c,0xb3,0xb9,0x89,0x22,0x28,0xd8,0xf1,0xdf,0x57,0x56,0x92,0xe4,0xd0 };
    const uint8_t PLAINTEXT[] = { 0x8d,0x3a,0xa1,0x96,0xec,0x3d,0x7c,0x9b,0x5b,0xb1,0x22,0xe7,0xfe,0x77,0xfb,0x12,0x95,0xa6,0xda,0x75,0xab,0xe5,0xd3,0xa5,0x10,0x19,0x4d,0x3a,0x8a,0x41,0x57,0xd5,0xc8,0x9d,0x40,0x61,0x97,0x16,0x61,0x98,0x59,0xda,0x3e,0xc9,0xb2,0x47,0xce,0xd9 };
    const uint8_t CIPHERTEXT[] = { 0x60,0x8e,0x82,0xc7,0xab,0x04,0x00,0x7a,0xdb,0x22,0xe3,0x89,0xa4,0x47,0x97,0xfe,0xd7,0xde,0x09,0x0c,0x8c,0x03,0xca,0x8a,0x2c,0x5a,0xcd,0x9e,0x84,0xdf,0x37,0xfb,0xc5,0x8c,0xe8,0xed,0xb2,0x93,0xe9,0x8f,0x02,0xb6,0x40,0xd6,0xd1,0xd7,0x24,0x64 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cbc(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CBCMMT256-ENCRYPT-3", "[CBC][MMT][256][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0x04,0x93,0xff,0x63,0x71,0x08,0xaf,0x6a,0x5b,0x8e,0x90,0xac,0x1f,0xdf,0x03,0x5a,0x3d,0x4b,0xaf,0xd1,0xaf,0xb5,0x73,0xbe,0x7a,0xde,0x9e,0x86,0x82,0xe6,0x63,0xe5 };
    const uint8_t IV[] = { 0xc0,0xcd,0x2b,0xeb,0xcc,0xbb,0x6c,0x49,0x92,0x0b,0xd5,0x48,0x2a,0xc7,0x56,0xe8 };
    const uint8_t PLAINTEXT[] = { 0x8b,0x37,0xf9,0x14,0x8d,0xf4,0xbb,0x25,0x95,0x6b,0xe6,0x31,0x0c,0x73,0xc8,0xdc,0x58,0xea,0x97,0x14,0xff,0x49,0xb6,0x43,0x10,0x7b,0x34,0xc9,0xbf,0xf0,0x96,0xa9,0x4f,0xed,0xd6,0x82,0x35,0x26,0xab,0xc2,0x7a,0x8e,0x0b,0x16,0x61,0x6e,0xee,0x25,0x4a,0xb4,0x56,0x7d,0xd6,0x8e,0x8c,0xcd,0x4c,0x38,0xac,0x56,0x3b,0x13,0x63,0x9c };
    const uint8_t CIPHERTEXT[] = { 0x05,0xd5,0xc7,0x77,0x29,0x42,0x1b,0x08,0xb7,0x37,0xe4,0x11,0x19,0xfa,0x44,0x38,0xd1,0xf5,0x70,0xcc,0x77,0x2a,0x4d,0x6c,0x3d,0xf7,0xff,0xed,0xa0,0x38,0x4e,0xf8,0x42,0x88,0xce,0x37,0xfc,0x4c,0x4c,0x7d,0x11,0x25,0xa4,0x99,0xb0,0x51,0x36,0x4c,0x38,0x9f,0xd6,0x39,0xbd,0xda,0x64,0x7d,0xaa,0x3b,0xda,0xda,0xb2,0xeb,0x55,0x94 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cbc(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CBCMMT256-ENCRYPT-4", "[CBC][MMT][256][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0x9a,0xdc,0x8f,0xbd,0x50,0x6e,0x03,0x2a,0xf7,0xfa,0x20,0xcf,0x53,0x43,0x71,0x9d,0xe6,0xd1,0x28,0x8c,0x15,0x8c,0x63,0xd6,0x87,0x8a,0xaf,0x64,0xce,0x26,0xca,0x85 };
    const uint8_t IV[] = { 0x11,0x95,0x8d,0xc6,0xab,0x81,0xe1,0xc7,0xf0,0x16,0x31,0xe9,0x94,0x4e,0x62,0x0f };
    const uint8_t PLAINTEXT[] = { 0xc7,0x91,0x7f,0x84,0xf7,0x47,0xcd,0x8c,0x4b,0x4f,0xed,0xc2,0x21,0x9b,0xdb,0xc5,0xf4,0xd0,0x75,0x88,0x38,0x9d,0x82,0x48,0x85,0x4c,0xf2,0xc2,0xf8,0x96,0x67,0xa2,0xd7,0xbc,0xf5,0x3e,0x73,0xd3,0x26,0x84,0x53,0x5f,0x42,0x31,0x8e,0x24,0xcd,0x45,0x79,0x39,0x50,0xb3,0x82,0x5e,0x5d,0x5c,0x5c,0x8f,0xcd,0x3e,0x5d,0xda,0x4c,0xe9,0x24,0x6d,0x18,0x33,0x7e,0xf3,0x05,0x2d,0x8b,0x21,0xc5,0x56,0x1c,0x8b,0x66,0x0e };
    const uint8_t CIPHERTEXT[] = { 0x9c,0x99,0xe6,0x82,0x36,0xbb,0x2e,0x92,0x9d,0xb1,0x08,0x9c,0x77,0x50,0xf1,0xb3,0x56,0xd3,0x9a,0xb9,0xd0,0xc4,0x0c,0x3e,0x2f,0x05,0x10,0x8a,0xe9,0xd0,0xc3,0x0b,0x04,0x83,0x2c,0xcd,0xbd,0xc0,0x8e,0xbf,0xa4,0x26,0xb7,0xf5,0xef,0xde,0x98,0x6e,0xd0,0x57,0x84,0xce,0x36,0x81,0x93,0xbb,0x36,0x99,0xbc,0x69,0x10,0x65,0xac,0x62,0xe2,0x58,0xb9,0xaa,0x4c,0xc5,0x57,0xe2,0xb4,0x5b,0x49,0xce,0x05,0x51,0x1e,0x65 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cbc(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CBCMMT256-ENCRYPT-5", "[CBC][MMT][256][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0x73,0xb8,0xfa,0xf0,0x0b,0x33,0x02,0xac,0x99,0x85,0x5c,0xf6,0xf9,0xe9,0xe4,0x85,0x18,0x69,0x0a,0x59,0x06,0xa4,0x86,0x9d,0x4d,0xcf,0x48,0xd2,0x82,0xfa,0xae,0x2a };
    const uint8_t IV[] = { 0xb3,0xcb,0x97,0xa8,0x0a,0x53,0x99,0x12,0xb8,0xc2,0x1f,0x45,0x0d,0x3b,0x93,0x95 };
    const uint8_t PLAINTEXT[] = { 0x3a,0xde,0xa6,0xe0,0x6e,0x42,0xc4,0xf0,0x41,0x02,0x14,0x91,0xf2,0x77,0x5e,0xf6,0x37,0x8c,0xb0,0x88,0x24,0x16,0x5e,0xdc,0x4f,0x64,0x48,0xe2,0x32,0x17,0x5b,0x60,0xd0,0x34,0x5b,0x9f,0x9c,0x78,0xdf,0x65,0x96,0xec,0x9d,0x22,0xb7,0xb9,0xe7,0x6e,0x8f,0x3c,0x76,0xb3,0x2d,0x5d,0x67,0x27,0x3f,0x1d,0x83,0xfe,0x7a,0x6f,0xc3,0xdd,0x3c,0x49,0x13,0x91,0x70,0xfa,0x57,0x01,0xb3,0xbe,0xac,0x61,0xb4,0x90,0xf0,0xa9,0xe1,0x3f,0x84,0x46,0x40,0xc4,0x50,0x0f,0x9a,0xd3,0x08,0x7a,0xdf,0xb0,0xae,0x10 };
    const uint8_t CIPHERTEXT[] = { 0xac,0x3d,0x6d,0xba,0xfe,0x2e,0x0f,0x74,0x06,0x32,0xfd,0x9e,0x82,0x0b,0xf6,0x04,0x4c,0xd5,0xb1,0x55,0x1c,0xbb,0x9c,0xc0,0x3c,0x0b,0x25,0xc3,0x9c,0xcb,0x7f,0x33,0xb8,0x3a,0xac,0xfc,0xa4,0x0a,0x32,0x65,0xf2,0xbb,0xff,0x87,0x91,0x53,0x44,0x8a,0xca,0xcb,0x88,0xfc,0xfb,0x3b,0xb7,0xb1,0x0f,0xe4,0x63,0xa6,0x8c,0x01,0x09,0xf0,0x28,0x38,0x2e,0x3e,0x55,0x7b,0x1a,0xdf,0x02,0xed,0x64,0x8a,0xb6,0xbb,0x89,0x5d,0xf0,0x20,0x5d,0x26,0xeb,0xbf,0xa9,0xa5,0xfd,0x8c,0xeb,0xd8,0xe4,0xbe,0xe3,0xdc };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cbc(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CBCMMT256-ENCRYPT-6", "[CBC][MMT][256][ENCRYPT][n6]") {
    const uint8_t KEY[] = { 0x9d,0xdf,0x37,0x45,0x89,0x65,0x04,0xff,0x36,0x0a,0x51,0xa3,0xeb,0x49,0xc0,0x1b,0x79,0xfc,0xce,0xbc,0x71,0xc3,0xab,0xcb,0x94,0xa9,0x49,0x40,0x8b,0x05,0xb2,0xc9 };
    const uint8_t IV[] = { 0xe7,0x90,0x26,0x63,0x9d,0x4a,0xa2,0x30,0xb5,0xcc,0xff,0xb0,0xb2,0x9d,0x79,0xbc };
    const uint8_t PLAINTEXT[] = { 0xcf,0x52,0xe5,0xc3,0x95,0x4c,0x51,0xb9,0x4c,0x9e,0x38,0xac,0xb8,0xc9,0xa7,0xc7,0x6a,0xeb,0xda,0xa9,0x94,0x3e,0xae,0x0a,0x1c,0xe1,0x55,0xa2,0xef,0xdb,0x4d,0x46,0x98,0x5d,0x93,0x55,0x11,0x47,0x14,0x52,0xd9,0xee,0x64,0xd2,0x46,0x1c,0xb2,0x99,0x1d,0x59,0xfc,0x00,0x60,0x69,0x7f,0x9a,0x67,0x16,0x72,0x16,0x32,0x30,0xf3,0x67,0xfe,0xd1,0x42,0x23,0x16,0xe5,0x2d,0x29,0xec,0xea,0xcb,0x87,0x68,0xf5,0x6d,0x9b,0x80,0xf6,0xd2,0x78,0x09,0x3c,0x9a,0x8a,0xcd,0x3c,0xfd,0x7e,0xdd,0x8e,0xbd,0x5c,0x29,0x38,0x59,0xf6,0x4d,0x2f,0x84,0x86,0xae,0x1b,0xd5,0x93,0xc6,0x5b,0xc0,0x14 };
    const uint8_t CIPHERTEXT[] = { 0x34,0xdf,0x56,0x1b,0xd2,0xcf,0xeb,0xbc,0xb7,0xaf,0x3b,0x4b,0x8d,0x21,0xca,0x52,0x58,0x31,0x2e,0x7e,0x2e,0x4e,0x53,0x8e,0x35,0xad,0x24,0x90,0xb6,0x11,0x2f,0x0d,0x7f,0x14,0x8f,0x6a,0xa8,0xd5,0x22,0xa7,0xf3,0xc6,0x1d,0x78,0x5b,0xd6,0x67,0xdb,0x0e,0x1d,0xc4,0x60,0x6c,0x31,0x8e,0xa4,0xf2,0x6a,0xf4,0xfe,0x7d,0x11,0xd4,0xdc,0xff,0x04,0x56,0x51,0x1b,0x4a,0xed,0x1a,0x0d,0x91,0xba,0x4a,0x1f,0xd6,0xcd,0x90,0x29,0x18,0x7b,0xc5,0x88,0x1a,0x5a,0x07,0xfe,0x02,0x04,0x9d,0x39,0x36,0x8e,0x83,0x13,0x9b,0x12,0x82,0x5b,0xae,0x2c,0x7b,0xe8,0x1e,0x6f,0x12,0xc6,0x1b,0xb5,0xc5 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cbc(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CBCMMT256-ENCRYPT-7", "[CBC][MMT][256][ENCRYPT][n7]") {
    const uint8_t KEY[] = { 0x45,0x8b,0x67,0xbf,0x21,0x2d,0x20,0xf3,0xa5,0x7f,0xce,0x39,0x20,0x65,0x58,0x2d,0xce,0xfb,0xf3,0x81,0xaa,0x22,0x94,0x9f,0x83,0x38,0xab,0x90,0x52,0x26,0x0e,0x1d };
    const uint8_t IV[] = { 0x4c,0x12,0xef,0xfc,0x59,0x63,0xd4,0x04,0x59,0x60,0x26,0x75,0x15,0x3e,0x96,0x49 };
    const uint8_t PLAINTEXT[] = { 0x25,0x6f,0xd7,0x3c,0xe3,0x5a,0xe3,0xea,0x9c,0x25,0xdd,0x2a,0x94,0x54,0x49,0x3e,0x96,0xd8,0x63,0x3f,0xe6,0x33,0xb5,0x61,0x76,0xdc,0xe8,0x78,0x5c,0xe5,0xdb,0xbb,0x84,0xdb,0xf2,0xc8,0xa2,0xee,0xb1,0xe9,0x6b,0x51,0x89,0x96,0x05,0xe4,0xf1,0x3b,0xbc,0x11,0xb9,0x3b,0xf6,0xf3,0x9b,0x34,0x69,0xbe,0x14,0x85,0x8b,0x5b,0x72,0x0d,0x4a,0x52,0x2d,0x36,0xfe,0xed,0x7a,0x32,0x9c,0x9b,0x1e,0x85,0x2c,0x92,0x80,0xc4,0x7d,0xb8,0x03,0x9c,0x17,0xc4,0x92,0x15,0x71,0xa0,0x7d,0x18,0x64,0x12,0x83,0x30,0xe0,0x9c,0x30,0x8d,0xde,0xa1,0x69,0x4e,0x95,0xc8,0x45,0x00,0xf1,0xa6,0x1e,0x61,0x41,0x97,0xe8,0x6a,0x30,0xec,0xc2,0x8d,0xf6,0x4c,0xcb,0x3c,0xcf,0x54,0x37,0xaa };
    const uint8_t CIPHERTEXT[] = { 0x90,0xb7,0xb9,0x63,0x0a,0x23,0x78,0xf5,0x3f,0x50,0x1a,0xb7,0xbe,0xff,0x03,0x91,0x55,0x00,0x80,0x71,0xbc,0x84,0x38,0xe7,0x89,0x93,0x2c,0xfd,0x3e,0xb1,0x29,0x91,0x95,0x46,0x5e,0x66,0x33,0x84,0x94,0x63,0xfd,0xb4,0x43,0x75,0x27,0x8e,0x2f,0xdb,0x13,0x10,0x82,0x1e,0x64,0x92,0xcf,0x80,0xff,0x15,0xcb,0x77,0x25,0x09,0xfb,0x42,0x6f,0x3a,0xee,0xe2,0x7b,0xd4,0x93,0x88,0x82,0xfd,0x2a,0xe6,0xb5,0xbd,0x9d,0x91,0xfa,0x4a,0x43,0xb1,0x7b,0xb4,0x39,0xeb,0xbe,0x59,0xc0,0x42,0x31,0x01,0x63,0xa8,0x2a,0x5f,0xe5,0x38,0x87,0x96,0xee,0xe3,0x5a,0x18,0x1a,0x12,0x71,0xf0,0x0b,0xe2,0x9b,0x85,0x2d,0x8f,0xa7,0x59,0xba,0xd0,0x1f,0xf4,0x67,0x8f,0x01,0x05,0x94,0xcd };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cbc(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CBCMMT256-ENCRYPT-8", "[CBC][MMT][256][ENCRYPT][n8]") {
    const uint8_t KEY[] = { 0xd2,0x41,0x2d,0xb0,0x84,0x5d,0x84,0xe5,0x73,0x2b,0x8b,0xbd,0x64,0x29,0x57,0x47,0x3b,0x81,0xfb,0x99,0xca,0x8b,0xff,0x70,0xe7,0x92,0x0d,0x16,0xc1,0xdb,0xec,0x89 };
    const uint8_t IV[] = { 0x51,0xc6,0x19,0xfc,0xf0,0xb2,0x3f,0x0c,0x79,0x25,0xf4,0x00,0xa6,0xca,0xcb,0x6d };
    const uint8_t PLAINTEXT[] = { 0x02,0x60,0x06,0xc4,0xa7,0x1a,0x18,0x0c,0x99,0x29,0x82,0x4d,0x9d,0x09,0x5b,0x8f,0xaa,0xa8,0x6f,0xc4,0xfa,0x25,0xec,0xac,0x61,0xd8,0x5f,0xf6,0xde,0x92,0xdf,0xa8,0x70,0x26,0x88,0xc0,0x2a,0x28,0x2c,0x1b,0x8a,0xf4,0x44,0x97,0x07,0xf2,0x2d,0x75,0xe9,0x19,0x91,0x01,0x5d,0xb2,0x23,0x74,0xc9,0x5f,0x8f,0x19,0x5d,0x5b,0xb0,0xaf,0xeb,0x03,0x04,0x0f,0xf8,0x96,0x5e,0x0e,0x13,0x39,0xdb,0xa5,0x65,0x3e,0x17,0x4f,0x8a,0xa5,0xa1,0xb3,0x9f,0xe3,0xac,0x83,0x9c,0xe3,0x07,0xa4,0xe4,0x4b,0x4f,0x8f,0x1b,0x00,0x63,0xf7,0x38,0xec,0x18,0xac,0xdb,0xff,0x2e,0xbf,0xe0,0x73,0x83,0xe7,0x34,0x55,0x87,0x23,0xe7,0x41,0xf0,0xa1,0x83,0x6d,0xaf,0xdf,0x9d,0xe8,0x22,0x10,0xa9,0x24,0x8b,0xc1,0x13,0xb3,0xc1,0xbc,0x8b,0x4e,0x25,0x2c,0xa0,0x1b,0xd8,0x03 };
    const uint8_t CIPHERTEXT[] = { 0x02,0x54,0xb2,0x34,0x63,0xbc,0xab,0xec,0x5a,0x39,0x5e,0xb7,0x4c,0x8f,0xb0,0xeb,0x13,0x7a,0x07,0xbc,0x6f,0x5e,0x9f,0x61,0xec,0x0b,0x05,0x7d,0xe3,0x05,0x71,0x4f,0x8f,0xa2,0x94,0x22,0x1c,0x91,0xa1,0x59,0xc3,0x15,0x93,0x9b,0x81,0xe3,0x00,0xee,0x90,0x21,0x92,0xec,0x5f,0x15,0x25,0x44,0x28,0xd8,0x77,0x2f,0x79,0x32,0x4e,0xc4,0x32,0x98,0xca,0x21,0xc0,0x0b,0x37,0x02,0x73,0xee,0x5e,0x5e,0xd9,0x0e,0x43,0xef,0xa1,0xe0,0x5a,0x5d,0x17,0x12,0x09,0xfe,0x34,0xf9,0xf2,0x92,0x37,0xdb,0xa2,0xa6,0x72,0x66,0x50,0xfd,0x3b,0x13,0x21,0x74,0x7d,0x12,0x08,0x86,0x3c,0x6c,0x3c,0x6b,0x3e,0x2d,0x87,0x9a,0xb5,0xf2,0x57,0x82,0xf0,0x8b,0xa8,0xf2,0xab,0xbe,0x63,0xe0,0xbe,0xdb,0x4a,0x22,0x7e,0x81,0xaf,0xb3,0x6b,0xb6,0x64,0x55,0x08,0x35,0x6d,0x34 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cbc(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CBCMMT256-ENCRYPT-9", "[CBC][MMT][256][ENCRYPT][n9]") {
    const uint8_t KEY[] = { 0x48,0xbe,0x59,0x7e,0x63,0x2c,0x16,0x77,0x23,0x24,0xc8,0xd3,0xfa,0x1d,0x9c,0x5a,0x9e,0xcd,0x01,0x0f,0x14,0xec,0x5d,0x11,0x0d,0x3b,0xfe,0xc3,0x76,0xc5,0x53,0x2b };
    const uint8_t IV[] = { 0xd6,0xd5,0x81,0xb8,0xcf,0x04,0xeb,0xd3,0xb6,0xea,0xa1,0xb5,0x3f,0x04,0x7e,0xe1 };
    const uint8_t PLAINTEXT[] = { 0x0c,0x63,0xd4,0x13,0xd3,0x86,0x45,0x70,0xe7,0x0b,0xb6,0x61,0x8b,0xf8,0xa4,0xb9,0x58,0x55,0x86,0x68,0x8c,0x32,0xbb,0xa0,0xa5,0xec,0xc1,0x36,0x2f,0xad,0xa7,0x4a,0xda,0x32,0xc5,0x2a,0xcf,0xd1,0xaa,0x74,0x44,0xba,0x56,0x7b,0x4e,0x7d,0xaa,0xec,0xf7,0xcc,0x1c,0xb2,0x91,0x82,0xaf,0x16,0x4a,0xe5,0x23,0x2b,0x00,0x28,0x68,0x69,0x56,0x35,0x59,0x98,0x07,0xa9,0xa7,0xf0,0x7a,0x1f,0x13,0x7e,0x97,0xb1,0xe1,0xc9,0xda,0xbc,0x89,0xb6,0xa5,0xe4,0xaf,0xa9,0xdb,0x58,0x55,0xed,0xaa,0x57,0x50,0x56,0xa8,0xf4,0xf8,0x24,0x22,0x16,0x24,0x2b,0xb0,0xc2,0x56,0x31,0x0d,0x9d,0x32,0x98,0x26,0xac,0x35,0x3d,0x71,0x5f,0xa3,0x9f,0x80,0xce,0xc1,0x44,0xd6,0x42,0x45,0x58,0xf9,0xf7,0x0b,0x98,0xc9,0x20,0x09,0x6e,0x0f,0x2c,0x85,0x5d,0x59,0x48,0x85,0xa0,0x06,0x25,0x88,0x0e,0x9d,0xfb,0x73,0x41,0x63,0xce,0xce,0xf7,0x2c,0xf0,0x30,0xb8 };
    const uint8_t CIPHERTEXT[] = { 0xfc,0x58,0x73,0xe5,0x0d,0xe8,0xfa,0xf4,0xc6,0xb8,0x4b,0xa7,0x07,0xb0,0x85,0x4e,0x9d,0xb9,0xab,0x2e,0x9f,0x7d,0x70,0x7f,0xbb,0xa3,0x38,0xc6,0x84,0x3a,0x18,0xfc,0x6f,0xac,0xeb,0xaf,0x66,0x3d,0x26,0x29,0x6f,0xb3,0x29,0xb4,0xd2,0x6f,0x18,0x49,0x4c,0x79,0xe0,0x9e,0x77,0x96,0x47,0xf9,0xba,0xfa,0x87,0x48,0x96,0x30,0xd7,0x9f,0x43,0x01,0x61,0x0c,0x23,0x00,0xc1,0x9d,0xbf,0x31,0x48,0xb7,0xca,0xc8,0xc4,0xf4,0x94,0x41,0x02,0x75,0x4f,0x33,0x2e,0x92,0xb6,0xf7,0xc5,0xe7,0x5b,0xc6,0x17,0x9e,0xb8,0x77,0xa0,0x78,0xd4,0x71,0x90,0x09,0x02,0x17,0x44,0xc1,0x4f,0x13,0xfd,0x2a,0x55,0xa2,0xb9,0xc4,0x4d,0x18,0x00,0x06,0x85,0xa8,0x45,0xa4,0xf6,0x32,0xc7,0xc5,0x6a,0x77,0x30,0x6e,0xfa,0x66,0xa2,0x4d,0x05,0xd0,0x88,0xdc,0xd7,0xc1,0x3f,0xe2,0x4f,0xc4,0x47,0x27,0x59,0x65,0xdb,0x9e,0x4d,0x37,0xfb,0xc9,0x30,0x44,0x48,0xcd };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_cbc(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("CBCMMT256-DECRYPT-0", "[CBC][MMT][256][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0x43,0xe9,0x53,0xb2,0xae,0xa0,0x8a,0x3a,0xd5,0x2d,0x18,0x2f,0x58,0xc7,0x2b,0x9c,0x60,0xfb,0xe4,0xa9,0xca,0x46,0xa3,0xcb,0x89,0xe3,0x86,0x38,0x45,0xe2,0x2c,0x9e };
    const uint8_t IV[] = { 0xdd,0xbb,0xb0,0x17,0x3f,0x1e,0x2d,0xeb,0x23,0x94,0xa6,0x2a,0xa2,0xa0,0x24,0x0e };
    const uint8_t PLAINTEXT[] = { 0x07,0x27,0x0d,0x0e,0x63,0xaa,0x36,0xda,0xed,0x8c,0x6a,0xde,0x13,0xac,0x1a,0xf1 };
    const uint8_t CIPHERTEXT[] = { 0xd5,0x1d,0x19,0xde,0xd5,0xca,0x4a,0xe1,0x4b,0x2b,0x20,0xb0,0x27,0xff,0xb0,0x20 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cbc(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CBCMMT256-DECRYPT-1", "[CBC][MMT][256][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0xad,0xdf,0x88,0xc1,0xab,0x99,0x7e,0xb5,0x8c,0x04,0x55,0x28,0x8c,0x3a,0x4f,0xa3,0x20,0xad,0xa8,0xc1,0x8a,0x69,0xcc,0x90,0xaa,0x99,0xc7,0x3b,0x17,0x4d,0xfd,0xe6 };
    const uint8_t IV[] = { 0x60,0xcc,0x50,0xe0,0x88,0x75,0x32,0xe0,0xd4,0xf3,0xd2,0xf2,0x0c,0x3c,0x5d,0x58 };
    const uint8_t PLAINTEXT[] = { 0x98,0xa8,0xa9,0xd8,0x43,0x56,0xbf,0x40,0x3a,0x9c,0xcc,0x38,0x4a,0x06,0xfe,0x04,0x3d,0xfe,0xec,0xb8,0x9e,0x59,0xce,0x0c,0xb8,0xbd,0x0a,0x49,0x5e,0xf7,0x6c,0xf0 };
    const uint8_t CIPHERTEXT[] = { 0x6c,0xb4,0xe2,0xf4,0xdd,0xf7,0x9a,0x8e,0x08,0xc9,0x6c,0x7f,0x40,0x40,0xe8,0xa8,0x32,0x66,0xc0,0x7f,0xc8,0x8d,0xd0,0x07,0x4e,0xe2,0x5b,0x00,0xd4,0x45,0x98,0x5a };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cbc(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CBCMMT256-DECRYPT-2", "[CBC][MMT][256][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0x54,0x68,0x27,0x28,0xdb,0x50,0x35,0xeb,0x04,0xb7,0x96,0x45,0xc6,0x4a,0x95,0x60,0x6a,0xbb,0x6b,0xa3,0x92,0xb6,0x63,0x3d,0x79,0x17,0x3c,0x02,0x7c,0x5a,0xcf,0x77 };
    const uint8_t IV[] = { 0x2e,0xb9,0x42,0x97,0x77,0x28,0x51,0x96,0x3d,0xd3,0x9a,0x1e,0xb9,0x5d,0x43,0x8f };
    const uint8_t PLAINTEXT[] = { 0x0f,0xaa,0x5d,0x01,0xb9,0xaf,0xad,0x3b,0xb5,0x19,0x57,0x5d,0xaa,0xf4,0xc6,0x0a,0x5e,0xd4,0xca,0x2b,0xa2,0x0c,0x62,0x5b,0xc4,0xf0,0x87,0x99,0xad,0xdc,0xf8,0x9d,0x19,0x79,0x6d,0x1e,0xff,0x0b,0xd7,0x90,0xc6,0x22,0xdc,0x22,0xc1,0x09,0x4e,0xc7 };
    const uint8_t CIPHERTEXT[] = { 0xe4,0x04,0x6d,0x05,0x38,0x5a,0xb7,0x89,0xc6,0xa7,0x28,0x66,0xe0,0x83,0x50,0xf9,0x3f,0x58,0x3e,0x2a,0x00,0x5c,0xa0,0xfa,0xec,0xc3,0x2b,0x5c,0xfc,0x32,0x3d,0x46,0x1c,0x76,0xc1,0x07,0x30,0x76,0x54,0xdb,0x55,0x66,0xa5,0xbd,0x69,0x3e,0x22,0x7c };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cbc(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CBCMMT256-DECRYPT-3", "[CBC][MMT][256][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0x74,0x82,0xc4,0x70,0x04,0xae,0xf4,0x06,0x11,0x5c,0xa5,0xfd,0x49,0x97,0x88,0xd5,0x82,0xef,0xc0,0xb2,0x9d,0xc9,0xe9,0x51,0xb1,0xf9,0x59,0x40,0x66,0x93,0xa5,0x4f };
    const uint8_t IV[] = { 0x48,0x5e,0xbf,0x22,0x15,0xd2,0x0b,0x81,0x6e,0xa5,0x39,0x44,0x82,0x97,0x17,0xce };
    const uint8_t PLAINTEXT[] = { 0x82,0xfe,0xc6,0x64,0x46,0x6d,0x58,0x50,0x23,0x82,0x1c,0x2e,0x39,0xa0,0xc4,0x33,0x45,0x66,0x9a,0x41,0x24,0x4d,0x05,0x01,0x8a,0x23,0xd7,0x15,0x95,0x15,0xf8,0xff,0x4d,0x88,0xb0,0x1c,0xd0,0xeb,0x83,0x07,0x0d,0x00,0x77,0xe0,0x65,0xd7,0x4d,0x73,0x73,0x81,0x6b,0x61,0x50,0x57,0x18,0xf8,0xd4,0xf2,0x70,0x28,0x6a,0x59,0xd4,0x5e };
    const uint8_t CIPHERTEXT[] = { 0x6c,0x24,0xf1,0x9b,0x9c,0x0b,0x18,0xd7,0x12,0x6b,0xf6,0x80,0x90,0xcb,0x8a,0xe7,0x2d,0xb3,0xca,0x7e,0xab,0xb5,0x94,0xf5,0x06,0xaa,0xe7,0xa2,0x49,0x3e,0x53,0x26,0xa5,0xaf,0xae,0x4e,0xc4,0xd1,0x09,0x37,0x5b,0x56,0xe2,0xb6,0xff,0x4c,0x9c,0xf6,0x39,0xe7,0x2c,0x63,0xdc,0x81,0x14,0xc7,0x96,0xdf,0x95,0xb3,0xc6,0xb6,0x20,0x21 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cbc(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CBCMMT256-DECRYPT-4", "[CBC][MMT][256][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0x3a,0xe3,0x8d,0x4e,0xbf,0x7e,0x7f,0x6d,0xc0,0xa1,0xe3,0x1e,0x5e,0xfa,0x7c,0xa1,0x23,0xfd,0xc3,0x21,0xe5,0x33,0xe7,0x9f,0xed,0xd5,0x13,0x2c,0x59,0x99,0xef,0x5b };
    const uint8_t IV[] = { 0x36,0xd5,0x5d,0xc9,0xed,0xf8,0x66,0x9b,0xee,0xcd,0x9a,0x2a,0x02,0x90,0x92,0xb9 };
    const uint8_t PLAINTEXT[] = { 0x8d,0x22,0xdb,0x30,0xc4,0x25,0x3c,0x3e,0x3a,0xdd,0x96,0x85,0xc1,0x4d,0x55,0xb0,0x5f,0x7c,0xf7,0x62,0x6c,0x52,0xcc,0xcf,0xcb,0xe9,0xb9,0x9f,0xd8,0x91,0x36,0x63,0xb8,0xb1,0xf2,0x2e,0x27,0x7a,0x4c,0xc3,0xd0,0xe7,0xe9,0x78,0xa3,0x47,0x82,0xeb,0x87,0x68,0x67,0x55,0x6a,0xd4,0x72,0x84,0x86,0xd5,0xe8,0x90,0xea,0x73,0x82,0x43,0xe3,0x70,0x0a,0x69,0x6d,0x6e,0xb5,0x8c,0xd8,0x1c,0x0e,0x60,0xeb,0x12,0x1c,0x50 };
    const uint8_t CIPHERTEXT[] = { 0xd5,0x0e,0xa4,0x8c,0x89,0x62,0x96,0x2f,0x7c,0x3d,0x30,0x1f,0xa9,0xf8,0x77,0x24,0x50,0x26,0xc2,0x04,0xa7,0x77,0x12,0x92,0xcd,0xdc,0xa1,0xe7,0xff,0xeb,0xbe,0xf0,0x0e,0x86,0xd7,0x29,0x10,0xb7,0xd8,0xa7,0x56,0xdf,0xb4,0x5c,0x9f,0x10,0x40,0x97,0x8b,0xb7,0x48,0xca,0x53,0x7e,0xdd,0x90,0xb6,0x70,0xec,0xee,0x37,0x5e,0x15,0xd9,0x85,0x82,0xb9,0xf9,0x3b,0x63,0x55,0xad,0xc9,0xf8,0x0f,0x4f,0xb2,0x10,0x8f,0xb9 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cbc(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CBCMMT256-DECRYPT-5", "[CBC][MMT][256][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0xd3,0x0b,0xfc,0x0b,0x2a,0x19,0xd5,0xb8,0xb6,0xf8,0xf4,0x6a,0xb7,0xf4,0x44,0xee,0x13,0x6a,0x7f,0xa3,0xfb,0xda,0xf5,0x30,0xcc,0x3e,0x89,0x76,0x33,0x9a,0xfc,0xc4 };
    const uint8_t IV[] = { 0x80,0xbe,0x76,0xa7,0xf8,0x85,0xd2,0xc0,0x6b,0x37,0xd6,0xa5,0x28,0xfa,0xe0,0xcd };
    const uint8_t PLAINTEXT[] = { 0x0b,0x6e,0x2a,0x82,0x13,0x16,0x9b,0x3b,0x78,0xdb,0x6d,0xe3,0x24,0xe2,0x86,0xf0,0x36,0x60,0x44,0xe0,0x35,0xc6,0x97,0x0a,0xfb,0xf0,0xa1,0xa5,0xc3,0x2a,0x05,0xb2,0x4b,0xa7,0x06,0xcd,0x9c,0x66,0x09,0x73,0x76,0x51,0xa8,0x1b,0x2b,0xcf,0x4c,0x68,0x1d,0xc0,0x86,0x19,0x83,0xa5,0xae,0xc7,0x6e,0x6c,0x8b,0x24,0x41,0x12,0xd6,0x4d,0x48,0x9e,0x84,0x32,0x89,0x74,0x73,0x73,0x94,0xb8,0x3a,0x39,0x45,0x90,0x11,0x72,0x71,0x62,0x65,0x2b,0x7a,0xa7,0x93,0xbf,0xb1,0xb7,0x14,0x88,0xb7,0xde,0xc9,0x6b };
    const uint8_t CIPHERTEXT[] = { 0x31,0xe4,0x67,0x7a,0x17,0xae,0xd1,0x20,0xbd,0x3a,0xf6,0x9f,0xbb,0x0e,0x4b,0x64,0x5b,0x9e,0x8c,0x10,0x4e,0x28,0x0b,0x79,0x9d,0xdd,0x49,0xf1,0xe2,0x41,0xc3,0xcc,0xb7,0xd4,0x0e,0x1c,0x6f,0xf2,0x26,0xbf,0x04,0xf8,0x04,0x9c,0x51,0xa8,0x6e,0x29,0x81,0xcf,0x13,0x31,0xc8,0x24,0xd7,0xd4,0x51,0x74,0x6c,0xcf,0x77,0xfc,0x22,0xfd,0x37,0x17,0x00,0x1e,0xe5,0x19,0x13,0xd8,0x1f,0x7a,0x06,0xfb,0x00,0x37,0xf3,0x09,0x95,0x75,0x79,0xf6,0x95,0x67,0x0f,0x2c,0x4c,0x73,0x97,0xd2,0xd9,0x90,0x37,0x4e };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cbc(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CBCMMT256-DECRYPT-6", "[CBC][MMT][256][DECRYPT][n6]") {
    const uint8_t KEY[] = { 0x64,0xa2,0x56,0xa6,0x63,0x52,0x7e,0xbe,0xa7,0x1f,0x8d,0x77,0x09,0x90,0xb4,0xce,0xe4,0xa2,0xd3,0xaf,0xbf,0xd3,0x3f,0xb1,0x2c,0x7a,0xc3,0x00,0xef,0x59,0xe4,0x9a };
    const uint8_t IV[] = { 0x18,0xcc,0xe9,0x14,0x7f,0x29,0x5c,0x5c,0x00,0xdb,0xe0,0x42,0x40,0x89,0xd3,0xb4 };
    const uint8_t PLAINTEXT[] = { 0xf7,0xe0,0xf7,0x9c,0xfd,0xdd,0x15,0xed,0x36,0x00,0xab,0x2d,0x29,0xc5,0x6b,0xa3,0xc8,0xe9,0x6d,0x1a,0x89,0x6a,0xff,0x6d,0xec,0x77,0x3e,0x6e,0xa4,0x71,0x0a,0x77,0xf2,0xf4,0xec,0x64,0x6b,0x76,0xef,0xda,0x64,0x28,0xc1,0x75,0xd0,0x07,0xc8,0x4a,0xa9,0xf4,0xb1,0x8c,0x5e,0x1b,0xac,0x5f,0x27,0xf7,0x30,0x7b,0x73,0x76,0x55,0xee,0xe8,0x13,0xf7,0xe1,0xf5,0x88,0x0a,0x37,0xac,0x63,0xad,0x16,0x66,0xe7,0x88,0x30,0x83,0xb6,0x48,0x45,0x4d,0x45,0x78,0x6f,0x53,0xea,0x3d,0xb1,0xb5,0x12,0x92,0x91,0x13,0x8a,0xbe,0x40,0xc7,0x9f,0xcb,0x7a,0xb7,0xc6,0xf6,0xb9,0xea,0x13,0x3b,0x5f };
    const uint8_t CIPHERTEXT[] = { 0xd9,0x97,0x71,0x96,0x3b,0x7a,0xe5,0x20,0x2e,0x38,0x2f,0xf8,0xc0,0x6e,0x03,0x53,0x67,0x90,0x9c,0xd2,0x4f,0xe5,0xad,0xa7,0xf3,0xd3,0x9b,0xfa,0xeb,0x5d,0xe9,0x8b,0x04,0xea,0xf4,0x98,0x96,0x48,0xe0,0x01,0x12,0xf0,0xd2,0xaa,0xdb,0x8c,0x5f,0x21,0x57,0xb6,0x45,0x81,0x45,0x03,0x59,0x96,0x51,0x40,0xc1,0x41,0xe5,0xfb,0x63,0x1e,0x43,0x46,0x9d,0x65,0xd1,0xb7,0x37,0x0e,0xb3,0xb3,0x96,0x39,0x9f,0xec,0x32,0xcc,0xed,0x29,0x4a,0x5e,0xee,0x46,0xd6,0x54,0x7f,0x7b,0xbd,0x49,0xde,0xe1,0x48,0xb4,0xbc,0x31,0xd6,0xc4,0x93,0xcf,0xd2,0x8f,0x39,0x08,0xe3,0x6c,0xb6,0x98,0x62,0x9d };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cbc(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CBCMMT256-DECRYPT-7", "[CBC][MMT][256][DECRYPT][n7]") {
    const uint8_t KEY[] = { 0x31,0x35,0x8e,0x8a,0xf3,0x4d,0x6a,0xc3,0x1c,0x95,0x8b,0xbd,0x5c,0x8f,0xb3,0x3c,0x33,0x47,0x14,0xbf,0xfb,0x41,0x70,0x0d,0x28,0xb0,0x7f,0x11,0xcf,0xe8,0x91,0xe7 };
    const uint8_t IV[] = { 0x14,0x45,0x16,0x24,0x6a,0x75,0x2c,0x32,0x90,0x56,0xd8,0x84,0xda,0xf3,0xc8,0x9d };
    const uint8_t PLAINTEXT[] = { 0xcf,0xc1,0x55,0xa3,0x96,0x7d,0xe3,0x47,0xf5,0x8f,0xa2,0xe8,0xbb,0xeb,0x41,0x83,0xd6,0xd3,0x2f,0x74,0x27,0x15,0x5e,0x6a,0xb3,0x9c,0xdd,0xf2,0xe6,0x27,0xc5,0x72,0xac,0xae,0x02,0xf1,0xf2,0x43,0xf3,0xb7,0x84,0xe7,0x3e,0x21,0xe7,0xe5,0x20,0xea,0xcd,0x3b,0xef,0xaf,0xbe,0xe8,0x14,0x86,0x73,0x34,0xc6,0xee,0x8c,0x2f,0x0e,0xe7,0x37,0x6d,0x3c,0x72,0x72,0x8c,0xde,0x78,0x13,0x17,0x3d,0xbd,0xfe,0x33,0x57,0xde,0xac,0x41,0xd3,0xae,0x2a,0x04,0x22,0x9c,0x02,0x62,0xf2,0xd1,0x09,0xd0,0x1f,0x5d,0x03,0xe7,0xf8,0x48,0xfb,0x50,0xc2,0x88,0x49,0x14,0x6c,0x02,0xa2,0xf4,0xeb,0xf7,0xd7,0xff,0xe3,0xc9,0xd4,0x0e,0x31,0x97,0x0b,0xf1,0x51,0x87,0x36,0x72,0xef,0x2b };
    const uint8_t CIPHERTEXT[] = { 0xb3,0x2e,0x2b,0x17,0x1b,0x63,0x82,0x70,0x34,0xeb,0xb0,0xd1,0x90,0x9f,0x7e,0xf1,0xd5,0x1c,0x5f,0x82,0xc1,0xbb,0x9b,0xc2,0x6b,0xc4,0xac,0x4d,0xcc,0xde,0xe8,0x35,0x7d,0xca,0x61,0x54,0xc2,0x51,0x0a,0xe1,0xc8,0x7b,0x1b,0x42,0x2b,0x02,0xb6,0x21,0xbb,0x06,0xca,0xc2,0x80,0x02,0x38,0x94,0xfc,0xff,0x34,0x06,0xaf,0x08,0xee,0x9b,0xe1,0xdd,0x72,0x41,0x9b,0xec,0xcd,0xdf,0xf7,0x7c,0x72,0x2d,0x99,0x2c,0xdc,0xc8,0x7e,0x9c,0x74,0x86,0xf5,0x6a,0xb4,0x06,0xea,0x60,0x8d,0x8c,0x6a,0xeb,0x06,0x0c,0x64,0xcf,0x27,0x85,0xad,0x1a,0x15,0x91,0x47,0x56,0x7e,0x39,0xe3,0x03,0x37,0x0d,0xa4,0x45,0x24,0x75,0x26,0xd9,0x59,0x42,0xbf,0x4d,0x7e,0x88,0x05,0x71,0x78,0xb0 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cbc(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CBCMMT256-DECRYPT-8", "[CBC][MMT][256][DECRYPT][n8]") {
    const uint8_t KEY[] = { 0x5b,0x4b,0x69,0x33,0x98,0x91,0xdb,0x4e,0x33,0x37,0xc3,0x48,0x6f,0x43,0x9d,0xfb,0xd0,0xfb,0x2a,0x78,0x2c,0xa7,0x1e,0xf0,0x05,0x98,0x19,0xd5,0x16,0x69,0xd9,0x3c };
    const uint8_t IV[] = { 0x2b,0x28,0xa2,0xd1,0x9b,0xa9,0xec,0xd1,0x49,0xda,0xe9,0x66,0x22,0xc2,0x17,0x69 };
    const uint8_t PLAINTEXT[] = { 0xa0,0xbb,0x1d,0x2f,0xde,0xb7,0xe6,0xbf,0x34,0xc6,0x90,0xfe,0x7b,0x72,0xa5,0xe9,0xd6,0x57,0x96,0xaa,0x57,0x98,0x2f,0xe3,0x40,0xc2,0x86,0xd6,0x92,0x3d,0xbd,0xdb,0x42,0x65,0x66,0xff,0x58,0xe9,0xc0,0xb3,0xaf,0x52,0xe4,0xdb,0x44,0x6f,0x6c,0xc5,0xda,0xa5,0xbf,0xcf,0x4e,0x3c,0x85,0xdb,0x5a,0x56,0x38,0xe6,0x70,0xc3,0x70,0xcc,0xe1,0x28,0xdb,0x22,0xc9,0x75,0x42,0xa6,0x4a,0x63,0x84,0x6f,0x18,0xa2,0x28,0xd3,0x46,0x2a,0x11,0x37,0x6d,0xcb,0x71,0xf6,0x6e,0xc5,0x2e,0xbd,0xa4,0x74,0xf7,0xb6,0x75,0x29,0x15,0xb0,0x80,0x17,0x97,0x97,0x4b,0xc5,0x1e,0xb1,0x21,0x81,0x27,0xfe,0xd6,0x0f,0x10,0x09,0x43,0x0e,0xb5,0x08,0x9f,0xb3,0xba,0x5f,0x28,0xfa,0xd2,0x4c,0x51,0x8c,0xcd,0xdc,0x25,0x01,0x39,0x3c,0xeb,0x6d,0xff,0xc4,0x6a,0x15,0x94,0x21 };
    const uint8_t CIPHERTEXT[] = { 0xba,0x21,0xdb,0x8e,0xc1,0x70,0xfa,0x4d,0x73,0xcf,0xc3,0x81,0x68,0x7f,0x3f,0xa1,0x88,0xdd,0x2d,0x01,0x2b,0xef,0x48,0x00,0x7f,0x3d,0xc8,0x83,0x29,0xe2,0x2b,0xa3,0x2f,0xe2,0x35,0xa3,0x15,0xbe,0x36,0x25,0x46,0x46,0x8b,0x9d,0xb6,0xaf,0x67,0x05,0xc6,0xe5,0xd4,0xd3,0x68,0x22,0xf4,0x28,0x83,0xc0,0x8d,0x4a,0x99,0x4c,0xc4,0x54,0xa7,0xdb,0x29,0x2c,0x4c,0xa1,0xf4,0xb6,0x2e,0xbf,0x8e,0x47,0x9a,0x5d,0x54,0x5d,0x6a,0xf9,0x97,0x8d,0x2c,0xfe,0xe7,0xbc,0x80,0x99,0x91,0x92,0xc2,0xc8,0x66,0x2c,0xe9,0xb4,0xbe,0x11,0xaf,0x40,0xbd,0x68,0xf3,0xe2,0xd5,0x68,0x5b,0xb2,0x8c,0x0f,0x3d,0xc0,0x80,0x17,0xc0,0xab,0xa8,0x26,0x3e,0x6f,0xdc,0x45,0xed,0x7f,0x98,0x93,0xbf,0x14,0xfd,0x3a,0x86,0xc4,0x18,0xa3,0x5c,0x56,0x67,0xe6,0x42,0xd5,0x99,0x85 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cbc(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("CBCMMT256-DECRYPT-9", "[CBC][MMT][256][DECRYPT][n9]") {
    const uint8_t KEY[] = { 0x87,0x72,0x5b,0xd4,0x3a,0x45,0x60,0x88,0x14,0x18,0x07,0x73,0xf0,0xe7,0xab,0x95,0xa3,0xc8,0x59,0xd8,0x3a,0x21,0x30,0xe8,0x84,0x19,0x0e,0x44,0xd1,0x4c,0x69,0x96 };
    const uint8_t IV[] = { 0xe4,0x96,0x51,0x98,0x8e,0xbb,0xb7,0x2e,0xb8,0xbb,0x80,0xbb,0x9a,0xbb,0xca,0x34 };
    const uint8_t PLAINTEXT[] = { 0xbf,0xe5,0xc6,0x35,0x4b,0x7a,0x3f,0xf3,0xe1,0x92,0xe0,0x57,0x75,0xb9,0xb7,0x58,0x07,0xde,0x12,0xe3,0x8a,0x62,0x6b,0x8b,0xf0,0xe1,0x2d,0x5f,0xff,0x78,0xe4,0xf1,0x77,0x5a,0xa7,0xd7,0x92,0xd8,0x85,0x16,0x2e,0x66,0xd8,0x89,0x30,0xf9,0xc3,0xb2,0xcd,0xf8,0x65,0x4f,0x56,0x97,0x25,0x04,0x80,0x31,0x90,0x38,0x62,0x70,0xf0,0xaa,0x43,0x64,0x5d,0xb1,0x87,0xaf,0x41,0xfc,0xea,0x63,0x9b,0x1f,0x80,0x26,0xcc,0xdd,0x0c,0x23,0xe0,0xde,0x37,0x09,0x4a,0x8b,0x94,0x1e,0xcb,0x76,0x02,0x99,0x8a,0x4b,0x26,0x04,0xe6,0x9f,0xc0,0x42,0x19,0x58,0x5d,0x85,0x46,0x00,0xe0,0xad,0x6f,0x99,0xa5,0x3b,0x25,0x04,0x04,0x3c,0x08,0xb1,0xc3,0xe2,0x14,0xd1,0x7c,0xde,0x05,0x3c,0xbd,0xf9,0x1d,0xaa,0x99,0x9e,0xd5,0xb4,0x7c,0x37,0x98,0x3b,0xa3,0xee,0x25,0x4b,0xc5,0xc7,0x93,0x83,0x7d,0xaa,0xa8,0xc8,0x5c,0xfc,0x12,0xf7,0xf5,0x4f,0x69,0x9f };
    const uint8_t CIPHERTEXT[] = { 0x5b,0x97,0xa9,0xd4,0x23,0xf4,0xb9,0x74,0x13,0xf3,0x88,0xd9,0xa3,0x41,0xe7,0x27,0xbb,0x33,0x9f,0x8e,0x18,0xa3,0xfa,0xc2,0xf2,0xfb,0x85,0xab,0xdc,0x8f,0x13,0x5d,0xeb,0x30,0x05,0x4a,0x1a,0xfd,0xc9,0xb6,0xed,0x7d,0xa1,0x6c,0x55,0xeb,0xa6,0xb0,0xd4,0xd1,0x0c,0x74,0xe1,0xd9,0xa7,0xcf,0x8e,0xdf,0xae,0xaa,0x68,0x4a,0xc0,0xbd,0x9f,0x9d,0x24,0xba,0x67,0x49,0x55,0xc7,0x9d,0xc6,0xbe,0x32,0xae,0xe1,0xc2,0x60,0xb5,0x58,0xff,0x07,0xe3,0xa4,0xd4,0x9d,0x24,0x16,0x20,0x11,0xff,0x25,0x4d,0xb8,0xbe,0x07,0x8e,0x8a,0xd0,0x7e,0x64,0x8e,0x6b,0xf5,0x67,0x93,0x76,0xcb,0x43,0x21,0xa5,0xef,0x01,0xaf,0xe6,0xad,0x88,0x16,0xfc,0xc7,0x63,0x46,0x69,0xc8,0xc4,0x38,0x92,0x95,0xc9,0x24,0x1e,0x45,0xff,0xf3,0x9f,0x32,0x25,0xf7,0x74,0x50,0x32,0xda,0xee,0xbe,0x99,0xd4,0xb1,0x9b,0xcb,0x21,0x5d,0x1b,0xfd,0xb3,0x6e,0xda,0x2c,0x24 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_cbc(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

