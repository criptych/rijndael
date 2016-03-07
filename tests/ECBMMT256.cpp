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

TEST_CASE("ECBMMT256-ENCRYPT-0", "[ECB][MMT][256][ENCRYPT][n0]") {
    const uint8_t KEY[] = { 0xcc,0x22,0xda,0x78,0x7f,0x37,0x57,0x11,0xc7,0x63,0x02,0xbe,0xf0,0x97,0x9d,0x8e,0xdd,0xf8,0x42,0x82,0x9c,0x2b,0x99,0xef,0x3d,0xd0,0x4e,0x23,0xe5,0x4c,0xc2,0x4b };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0xcc,0xc6,0x2c,0x6b,0x0a,0x09,0xa6,0x71,0xd6,0x44,0x56,0x81,0x8d,0xb2,0x9a,0x4d };
    const uint8_t CIPHERTEXT[] = { 0xdf,0x86,0x34,0xca,0x02,0xb1,0x3a,0x12,0x5b,0x78,0x6e,0x1d,0xce,0x90,0x65,0x8b };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ecb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("ECBMMT256-ENCRYPT-1", "[ECB][MMT][256][ENCRYPT][n1]") {
    const uint8_t KEY[] = { 0x7a,0x52,0xe4,0xd3,0x42,0xaa,0x07,0x25,0x5a,0x7e,0x7c,0x34,0x26,0x6c,0xf7,0x30,0x2a,0xbe,0x2d,0x4d,0xd7,0xec,0x44,0x68,0xa4,0x61,0x87,0xee,0x61,0x82,0x5f,0xfa };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x7e,0x77,0x1c,0x6e,0xe4,0xb2,0x6d,0xb8,0x90,0x50,0xe9,0x82,0xba,0x7e,0x98,0x03,0xc8,0xda,0x34,0x60,0x64,0x34,0xdd,0x85,0xd2,0x91,0x0e,0x53,0x80,0x76,0xd0,0x01 };
    const uint8_t CIPHERTEXT[] = { 0xa9,0x1d,0x8b,0x2d,0xdf,0x37,0x52,0x0b,0xc4,0x69,0x47,0x0a,0xd0,0xdd,0x63,0x94,0x92,0x31,0x43,0xce,0x55,0x38,0x6b,0xeb,0x1f,0x9c,0x4b,0xd5,0x15,0x84,0x65,0x8e };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ecb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("ECBMMT256-ENCRYPT-2", "[ECB][MMT][256][ENCRYPT][n2]") {
    const uint8_t KEY[] = { 0x60,0x5c,0x41,0x39,0xc9,0x61,0xb4,0x96,0xca,0x51,0x48,0xf1,0xbd,0xb1,0xbb,0x19,0x01,0xf2,0x10,0x19,0x43,0xa0,0xec,0x10,0xfc,0xdc,0x40,0x3d,0x3b,0x0c,0x28,0x5a };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x68,0xc9,0x88,0x5b,0xa2,0xbe,0x03,0x18,0x1f,0x65,0xf1,0xe0,0x4e,0x83,0xd6,0xba,0x68,0x80,0x46,0x75,0x50,0xbc,0xf0,0x99,0xbe,0x26,0xdc,0x9d,0x9c,0x0a,0xf1,0x5a,0xb0,0x2a,0xba,0xc0,0x7c,0x11,0x6a,0xc8,0x62,0xa4,0x1d,0xa9,0x0c,0xfa,0x60,0x4f };
    const uint8_t CIPHERTEXT[] = { 0xa7,0x60,0x3d,0x29,0xbb,0xba,0x4c,0x77,0x20,0x8b,0xf2,0xf3,0xdf,0x9f,0x5e,0xc8,0x52,0x04,0xad,0xce,0x01,0x22,0x99,0xf2,0xcc,0xe7,0xb3,0x26,0xce,0x78,0xf5,0xcf,0x80,0x40,0x34,0x3d,0xd2,0x91,0xe8,0xcf,0x9f,0x36,0x45,0x72,0x63,0x68,0xdc,0x20 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ecb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("ECBMMT256-ENCRYPT-3", "[ECB][MMT][256][ENCRYPT][n3]") {
    const uint8_t KEY[] = { 0xf9,0x84,0xb0,0xf5,0x34,0xfc,0x0a,0xe2,0xc0,0xa8,0x59,0x3e,0x16,0xab,0x83,0x65,0xf2,0x5f,0xcc,0x9c,0x59,0x47,0xf9,0xa2,0xdb,0x45,0xb5,0x88,0x16,0x0d,0x35,0xc3 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x35,0x1f,0xee,0x09,0x91,0x22,0xe3,0x71,0xc4,0x83,0x0f,0x40,0x9c,0x6c,0x44,0x11,0x18,0x6d,0x22,0x17,0x6f,0x71,0x38,0xb0,0x54,0xf1,0x6b,0x3c,0x79,0x67,0x9c,0x2f,0x52,0x06,0x85,0x65,0x1b,0xa8,0xe4,0xb6,0x1c,0x08,0xdc,0xcb,0x2c,0x31,0x98,0x2f,0x74,0x36,0x31,0xa9,0x75,0x24,0xd2,0xca,0x4d,0x35,0x1a,0xc2,0x35,0x46,0xc1,0x78 };
    const uint8_t CIPHERTEXT[] = { 0x8b,0x9c,0x9e,0x69,0x2c,0x16,0xe7,0x05,0x98,0x18,0xe2,0x85,0xe8,0x5d,0x8f,0xa5,0x43,0x3d,0xee,0x2a,0xff,0x9f,0xec,0x61,0xd6,0xa0,0xa7,0x81,0xe2,0x4b,0x24,0xf6,0x49,0x02,0xfb,0xd1,0x8c,0xef,0x74,0x61,0xad,0x77,0x60,0xcf,0xb2,0x44,0x2f,0xb7,0x4f,0xfd,0x9b,0xe1,0x08,0xa3,0x86,0x54,0x5f,0x2a,0x21,0x64,0x30,0xef,0x16,0xfb };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ecb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("ECBMMT256-ENCRYPT-4", "[ECB][MMT][256][ENCRYPT][n4]") {
    const uint8_t KEY[] = { 0xba,0x42,0xb7,0x60,0xbb,0x5a,0x5d,0xe2,0x1a,0xcb,0x9a,0xba,0x21,0x4c,0x97,0x83,0xcd,0x71,0xea,0x84,0x1a,0xda,0x01,0x85,0x80,0xab,0xc4,0xe1,0xbe,0x3b,0x76,0xdd };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x4b,0x4b,0x12,0xd6,0xee,0x6f,0xc0,0xbf,0x98,0x7e,0xaa,0xfe,0x26,0x34,0xaa,0xd4,0x64,0x78,0x1f,0xf4,0xc8,0x3d,0x3f,0x8a,0x61,0xa6,0xaf,0x7c,0x0a,0x6d,0x51,0xf0,0xe3,0x85,0x5d,0x0e,0x02,0xfe,0xb3,0x07,0x65,0x2a,0x6f,0x56,0x2b,0xfe,0xbe,0x46,0x04,0xba,0xf1,0xb4,0xe7,0xcd,0xd0,0x16,0x03,0xf2,0x31,0xbc,0xf7,0xa0,0xc9,0x56,0x45,0xa1,0x41,0xb7,0x04,0x00,0x8c,0xd8,0xd6,0x29,0x79,0x20,0x1a,0x4c,0x84,0xe2 };
    const uint8_t CIPHERTEXT[] = { 0xfa,0x18,0xd2,0x5e,0x37,0xea,0x0c,0xe9,0x4f,0x09,0x49,0xef,0xc0,0xed,0xec,0xc6,0xa4,0x0f,0xad,0xa8,0xf0,0x07,0xfd,0x8e,0x76,0x0a,0xfe,0xd0,0xa8,0x3e,0xbb,0x35,0x0c,0x82,0xb0,0x3b,0xaa,0xa6,0xee,0x19,0xf7,0x91,0xbb,0x9b,0xd1,0xb4,0x4d,0x27,0xa7,0x6f,0xc6,0xeb,0x0e,0x1c,0x00,0x17,0xd6,0x87,0x76,0xed,0x69,0xa5,0x41,0x85,0x1a,0x73,0x2e,0x46,0xef,0x32,0x8d,0xef,0x06,0x4b,0xaf,0x6a,0x0a,0x75,0x55,0x88 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ecb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("ECBMMT256-ENCRYPT-5", "[ECB][MMT][256][ENCRYPT][n5]") {
    const uint8_t KEY[] = { 0x1d,0x29,0x07,0x9c,0xc3,0x4a,0xb5,0xa3,0xbc,0x71,0x3f,0x41,0x6a,0x12,0x9f,0x9d,0x26,0xad,0xa1,0x5f,0xca,0x45,0x8c,0xc2,0x73,0x14,0x04,0xea,0x85,0x7d,0x2f,0x79 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0xb3,0x68,0x09,0x19,0x81,0x32,0x51,0x8d,0x81,0x5a,0xa3,0x7f,0x32,0xf4,0x0d,0xd7,0xa9,0x52,0xec,0x8b,0xd6,0x33,0x55,0x70,0x08,0x37,0xb4,0x50,0xb3,0x96,0xb3,0x3c,0x72,0x12,0x5e,0x23,0x48,0x2a,0x84,0xa4,0x2b,0x91,0x60,0x21,0xc3,0xde,0x78,0x15,0x6f,0x85,0xc6,0xa7,0x89,0x06,0x16,0x7f,0xeb,0x64,0xaf,0xd8,0xb1,0xd9,0x35,0xd6,0x41,0xc8,0xce,0x1a,0x89,0xf3,0x84,0x95,0x88,0xee,0xeb,0x99,0x10,0xd4,0x03,0x36,0xca,0x38,0x5f,0xc3,0x7a,0x5e,0x87,0xbb,0x84,0xab,0x9c,0xcb,0xb0,0x5b,0x3a,0x28 };
    const uint8_t CIPHERTEXT[] = { 0x7a,0xe8,0x03,0xb1,0x49,0x14,0xd1,0x56,0x43,0x9f,0x58,0x0c,0x02,0xc5,0x92,0xbf,0x9a,0x41,0xb7,0xb8,0x0c,0x20,0x16,0x81,0x29,0xa3,0x3f,0xae,0x22,0x90,0x40,0x3f,0x01,0xa6,0xfa,0xbe,0x4f,0xea,0x7a,0xc7,0x70,0xff,0xbc,0x6c,0x42,0x1f,0x8e,0x01,0x3b,0x9e,0x83,0x16,0x74,0xef,0x17,0xeb,0x27,0xd4,0x46,0xdd,0xed,0x3b,0xaf,0x50,0x68,0x6b,0x80,0x9c,0x18,0xb6,0xbb,0xd5,0x88,0xcd,0x3c,0x74,0x23,0xb6,0x49,0x87,0xe9,0x16,0x4b,0x7e,0x1e,0x66,0x98,0x7d,0xc9,0x31,0x97,0x90,0xae,0x27,0xb3,0xe8 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ecb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("ECBMMT256-ENCRYPT-6", "[ECB][MMT][256][ENCRYPT][n6]") {
    const uint8_t KEY[] = { 0x2e,0x39,0xc5,0x85,0xce,0x49,0x00,0xd3,0x23,0xce,0x29,0x71,0x3b,0xeb,0xe7,0x3a,0x1b,0xe0,0x8a,0x0c,0xb2,0x2e,0x9f,0x13,0x10,0xfc,0xc1,0x4a,0xd4,0xb9,0xb2,0x3e };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0xe1,0x99,0x89,0x9e,0x1e,0x12,0xcf,0xfc,0xb2,0x89,0x09,0xae,0xc5,0x1b,0x36,0xc2,0xf9,0x6f,0xab,0x49,0xef,0x32,0xb9,0x65,0x0c,0xc3,0x8a,0xa3,0x7d,0x2f,0x4c,0x8b,0x78,0x5f,0x91,0x76,0xc5,0x90,0xf6,0xa0,0x7e,0x04,0x03,0x7e,0x13,0xf7,0x53,0x52,0x90,0xd5,0xf5,0xfc,0x23,0xaa,0x11,0x13,0xd9,0xda,0xcf,0x34,0xa8,0x12,0x74,0x9a,0xb2,0x7e,0xcf,0xef,0xc8,0x3d,0xd3,0x62,0x2d,0x12,0x85,0xfa,0x9d,0x5c,0x19,0x2a,0x8e,0x48,0x57,0xa5,0xb6,0x45,0x44,0x73,0xcd,0xb8,0xff,0x45,0x94,0xf1,0xe9,0x06,0x16,0x5e,0x08,0xb2,0x2e,0xff,0xae,0x6b,0x49,0x1a,0x55,0xca,0x6d,0x30,0xce,0x73 };
    const uint8_t CIPHERTEXT[] = { 0x2c,0x49,0x98,0x42,0x8e,0x72,0xf6,0xd9,0x6e,0x98,0x2a,0x31,0x6f,0x73,0xbf,0x2a,0x7d,0xa8,0x17,0x30,0x90,0x9b,0x65,0x40,0x34,0x89,0xab,0x92,0xad,0xa6,0xde,0x11,0x88,0x2d,0x08,0x74,0x2f,0x90,0xf0,0xf1,0x09,0xd3,0x42,0x0b,0x00,0xb8,0xab,0xe6,0x87,0x3f,0x4f,0xdd,0x14,0x74,0x92,0x3d,0xa2,0xc5,0xbd,0xea,0x2e,0x45,0x23,0xff,0xca,0x21,0x32,0x01,0x5e,0xcf,0x7c,0x9c,0xac,0x9d,0xe2,0xf9,0x56,0xb1,0x12,0xc4,0xba,0x8e,0x4c,0x8e,0x4b,0x35,0x4a,0x3d,0xf6,0xe4,0x65,0x2d,0x6a,0x77,0xae,0x98,0x2a,0x24,0xd1,0x5c,0xff,0x71,0xb9,0x79,0x53,0x8d,0x49,0x99,0x4f,0xd3,0x87,0x61 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ecb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("ECBMMT256-ENCRYPT-7", "[ECB][MMT][256][ENCRYPT][n7]") {
    const uint8_t KEY[] = { 0x85,0x40,0x5c,0x4f,0x0e,0xbb,0xe8,0xf2,0x92,0x28,0xf0,0x2f,0x1f,0xf1,0x84,0xe2,0xf5,0xe7,0x85,0x7e,0x89,0x33,0xc2,0xa1,0xd0,0x8f,0x61,0xec,0xb9,0xb6,0x81,0x11 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x0f,0x53,0x21,0xdb,0x6f,0xd9,0xd8,0x16,0xd8,0x8e,0x28,0x18,0x3a,0x73,0x9d,0x90,0x97,0x4e,0x76,0x09,0x5c,0xaa,0x9f,0x12,0xf1,0x1f,0xe4,0x9c,0x8f,0xd3,0x5f,0xa3,0x52,0x41,0x32,0x11,0x8f,0x39,0x7c,0xdf,0x67,0x28,0x85,0x7d,0x9c,0x9a,0x3c,0x74,0xa4,0xfd,0xe4,0x4a,0xfc,0xa8,0x0a,0xa5,0xbf,0x1c,0xba,0xb4,0x77,0x89,0xf2,0xcb,0x33,0x94,0x57,0x4d,0xda,0x57,0x27,0xcf,0xbe,0xa9,0x6f,0x7a,0x74,0xa0,0x7e,0xb1,0xe4,0x55,0x99,0xf4,0x9c,0xe7,0xf0,0x05,0x6a,0xc3,0xd1,0x49,0x29,0x22,0x1c,0x70,0xdb,0xd3,0xf7,0x59,0xf8,0x3a,0xc2,0x2f,0x06,0x99,0x4e,0xd9,0x6a,0x8e,0x49,0x91,0x7e,0xdd,0xfd,0xd2,0xe3,0x70,0x3b,0x78,0x19,0x9c,0x91,0x23,0x4c,0xa6,0xc3,0xdc };
    const uint8_t CIPHERTEXT[] = { 0x2a,0xc6,0xde,0x21,0x2d,0xa0,0x43,0x4b,0xea,0x9c,0xdd,0x73,0x32,0x63,0x73,0x07,0x13,0x1d,0x31,0xe8,0xc4,0xb0,0xc1,0xfd,0x02,0x29,0x8e,0x24,0x9b,0xfa,0x9f,0x64,0xf3,0x4a,0xae,0x45,0xfa,0xad,0xf7,0x9d,0x97,0x1a,0xe8,0x2b,0x03,0x3d,0x90,0x3f,0x6b,0x18,0xad,0xec,0x17,0x1e,0xc8,0x3c,0xcd,0x14,0x7b,0x44,0xd0,0x5d,0xec,0x5c,0xed,0xb5,0x74,0x53,0x4e,0x89,0x01,0x38,0x55,0x34,0xc3,0xf1,0xda,0xe4,0xae,0xbe,0xe0,0xeb,0x21,0x64,0x97,0x5e,0x8b,0x4e,0x85,0xa7,0xb5,0xa7,0x66,0xff,0xd8,0x24,0x78,0x85,0xc2,0xb6,0x42,0x9e,0xb6,0x59,0xb9,0x2c,0x8d,0x95,0x3a,0xf9,0x2b,0x54,0x51,0x79,0x33,0x56,0x66,0x54,0xd8,0x04,0x66,0x51,0x12,0xbe,0xc1,0x7f,0xf3,0xa4 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ecb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("ECBMMT256-ENCRYPT-8", "[ECB][MMT][256][ENCRYPT][n8]") {
    const uint8_t KEY[] = { 0xf1,0x57,0x28,0x5d,0xb0,0x0e,0x64,0xc2,0x79,0x16,0x68,0xa5,0x44,0x93,0x96,0x6e,0x30,0x39,0xa1,0x94,0x26,0x60,0x50,0x56,0xb9,0x5b,0x7e,0xac,0x51,0x06,0x66,0x7d };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x36,0x37,0xf7,0x1f,0x60,0xa4,0x30,0x32,0x29,0x80,0x34,0x9a,0xd4,0x14,0xfc,0xfd,0xc1,0x4f,0x87,0xe9,0x91,0x5d,0x21,0x0e,0x8b,0x7b,0xe5,0xaa,0x3e,0x09,0x81,0x44,0x68,0xe0,0x39,0x9d,0x17,0xe7,0x2f,0xe4,0x0e,0xe1,0xe1,0x29,0x6a,0x89,0xf3,0x14,0x86,0xe1,0x2f,0xd7,0x1b,0xc7,0xca,0x61,0xac,0xc9,0xe8,0xd4,0x21,0x3a,0x63,0x3a,0xb2,0x85,0xc8,0x74,0x06,0xc2,0xa3,0x72,0x9c,0x87,0xfd,0xaa,0x6b,0x01,0x22,0xc2,0xc5,0x43,0xa8,0x90,0x81,0xdd,0xac,0x45,0x59,0xb1,0x5f,0xe5,0x91,0x02,0xc2,0xfb,0xda,0xce,0xad,0x8a,0x75,0x5e,0x16,0x46,0x9b,0x1b,0x90,0x04,0x1d,0xa3,0x12,0x70,0x48,0x1c,0xfa,0xfe,0x0b,0xc9,0x51,0x23,0x5c,0xda,0x51,0xc4,0xd7,0x89,0x24,0xef,0xa8,0x62,0xef,0xc9,0xac,0xe2,0x0f,0xc7,0xd3,0x44,0xa3,0x21,0xc9,0x98,0x4a,0x84 };
    const uint8_t CIPHERTEXT[] = { 0xca,0x0a,0x68,0x3e,0x75,0x9c,0x13,0x12,0x92,0x8f,0xe0,0x11,0x98,0xf6,0x25,0xbb,0xa0,0x44,0xbb,0x90,0x03,0xe8,0x2b,0x92,0x79,0xb6,0x81,0x2f,0xee,0xfe,0x54,0xe3,0x0c,0xcc,0x0c,0xa5,0x1f,0xb8,0x58,0xeb,0xa9,0xed,0x46,0x67,0xe8,0x5c,0x14,0x6a,0x42,0x40,0x71,0xe7,0xbf,0x60,0x3f,0x1f,0x53,0x8e,0xad,0x57,0xa3,0xe2,0x9c,0x58,0x35,0x49,0xc0,0x8e,0x27,0x9b,0xb0,0x78,0xcc,0x51,0xe4,0x2e,0xeb,0x3d,0x24,0x43,0xda,0x96,0x51,0x92,0xcd,0x04,0x78,0xe8,0xd7,0xea,0x13,0x43,0xcf,0x90,0x19,0x6f,0x52,0x09,0x33,0xe3,0xaa,0xb6,0xdb,0x2d,0xcd,0x9a,0x76,0x53,0x4e,0x05,0x48,0x3e,0xea,0x2d,0x37,0x3d,0xea,0xe9,0x5d,0x62,0x13,0xb9,0x1d,0xb2,0xb9,0x6a,0xa6,0xad,0xce,0x72,0x7c,0xdf,0x7e,0x43,0xbd,0x01,0x97,0x8d,0x07,0xe0,0x24,0x1c,0xf1,0xc1 };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ecb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("ECBMMT256-ENCRYPT-9", "[ECB][MMT][256][ENCRYPT][n9]") {
    const uint8_t KEY[] = { 0x44,0xa2,0xb5,0xa7,0x45,0x3e,0x49,0xf3,0x82,0x61,0x90,0x4f,0x21,0xac,0x79,0x76,0x41,0xd1,0xbc,0xd8,0xdd,0xed,0xd2,0x93,0xf3,0x19,0x44,0x9f,0xe6,0x3b,0x29,0x48 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0xc9,0x1b,0x8a,0x7b,0x9c,0x51,0x17,0x84,0xb6,0xa3,0x7f,0x73,0xb2,0x90,0x51,0x6b,0xb9,0xef,0x1e,0x8d,0xf6,0x8d,0x89,0xbf,0x49,0x16,0x9e,0xac,0x40,0x39,0x65,0x0c,0x43,0x07,0xb6,0x26,0x0e,0x9c,0x4e,0x93,0x65,0x02,0x23,0x44,0x02,0x52,0xf5,0xc7,0xd3,0x1c,0x26,0xc5,0x62,0x09,0xcb,0xd0,0x95,0xbf,0x03,0x5b,0x97,0x05,0x88,0x0a,0x16,0x28,0x83,0x2d,0xaf,0x9d,0xa5,0x87,0xa6,0xe7,0x73,0x53,0xdb,0xbc,0xe1,0x89,0xf9,0x63,0x23,0x5d,0xf1,0x60,0xc0,0x08,0xa7,0x53,0xe8,0xcc,0xea,0x1e,0x07,0x32,0xaa,0x46,0x9a,0x97,0x65,0x9c,0x42,0xe6,0xe3,0x1c,0x16,0xa7,0x23,0x15,0x3e,0x39,0x95,0x8a,0xbe,0x5b,0x8a,0xd8,0x8f,0xf2,0xe8,0x9a,0xf4,0x06,0x22,0xca,0x0b,0x0d,0x67,0x29,0xa2,0x6c,0x1a,0xe0,0x4d,0x3b,0x83,0x67,0xb5,0x48,0xc4,0xa6,0x33,0x5f,0x0e,0x5a,0x9e,0xc9,0x14,0xbb,0x61,0x13,0xc0,0x5c,0xd0,0x11,0x25,0x52,0xbc,0x21 };
    const uint8_t CIPHERTEXT[] = { 0x05,0xd5,0x1a,0xf0,0xe2,0xb6,0x1e,0x2c,0x06,0xcb,0x1e,0x84,0x3f,0xee,0x31,0x72,0x82,0x5e,0x63,0xb5,0xd1,0xce,0x81,0x83,0xb7,0xe1,0xdb,0x62,0x68,0xdb,0x5a,0xa7,0x26,0x52,0x1f,0x46,0xe9,0x48,0x02,0x8a,0xa4,0x43,0xaf,0x9e,0xbd,0x8b,0x7c,0x6b,0xaf,0x95,0x80,0x67,0xab,0x0d,0x4a,0x8a,0xc5,0x30,0xec,0xbb,0x68,0xcd,0xfc,0x3e,0xb9,0x30,0x34,0xa4,0x28,0xeb,0x7e,0x8f,0x6a,0x38,0x13,0xce,0xa6,0x18,0x90,0x68,0xdf,0xec,0xfa,0x26,0x8b,0x7e,0xcd,0x59,0x87,0xf8,0xcb,0x27,0x32,0xc6,0x88,0x2b,0xbe,0xc8,0xf7,0x16,0xba,0xc2,0x54,0xd7,0x22,0x69,0x23,0x0a,0xec,0x5d,0xc7,0xf5,0xa6,0xb8,0x66,0xfd,0x30,0x52,0x42,0x55,0x2d,0x40,0x0f,0x5b,0x04,0x04,0xf1,0x9c,0xbf,0xe7,0x29,0x1f,0xab,0x69,0x0e,0xcf,0xe6,0x01,0x8c,0x43,0x09,0xfc,0x63,0x9d,0x1b,0x65,0xfc,0xb6,0x5e,0x64,0x3e,0xdb,0x0a,0xd1,0xf0,0x9c,0xfe,0x9c,0xee,0x4a };
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_encrypt_ecb(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

TEST_CASE("ECBMMT256-DECRYPT-0", "[ECB][MMT][256][DECRYPT][n0]") {
    const uint8_t KEY[] = { 0xa8,0x1f,0xd6,0xca,0x56,0x68,0x3d,0x0f,0x54,0x45,0x65,0x9d,0xde,0x4d,0x99,0x5d,0xc6,0x5f,0x4b,0xce,0x20,0x89,0x63,0x05,0x3e,0x28,0xd7,0xf2,0xdf,0x51,0x7c,0xe4 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x8b,0x2b,0x1b,0x22,0xf7,0x33,0xac,0x09,0xd1,0x19,0x6d,0x6b,0xe6,0xa8,0x7a,0x72 };
    const uint8_t CIPHERTEXT[] = { 0x41,0x54,0xc0,0xbe,0x71,0x07,0x29,0x45,0xd8,0x15,0x6f,0x5f,0x04,0x6d,0x19,0x8d };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ecb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("ECBMMT256-DECRYPT-1", "[ECB][MMT][256][DECRYPT][n1]") {
    const uint8_t KEY[] = { 0xbc,0x14,0x15,0xaa,0x11,0x9c,0x29,0xa9,0xa2,0x7c,0x0e,0xa9,0xd1,0x9e,0xd5,0x0a,0xce,0x86,0xc4,0x88,0xb8,0xe3,0x9d,0x6a,0x05,0x64,0x24,0xfb,0x23,0xcd,0xdb,0x3e };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0xa8,0xfa,0xb5,0x37,0x90,0xaf,0x35,0x19,0xcf,0x21,0x97,0x8e,0x3c,0xf0,0x3b,0xa8,0xe5,0x2b,0x90,0x2b,0xe2,0x33,0x11,0xbf,0x17,0xf1,0xad,0x2c,0x5f,0xf3,0x7c,0x16 };
    const uint8_t CIPHERTEXT[] = { 0x0a,0x5f,0x32,0x78,0xd7,0xd9,0x66,0x32,0xe0,0x50,0x83,0x91,0xe8,0x13,0xf0,0x6b,0x35,0xd8,0xd7,0x54,0xdd,0xf5,0x86,0x72,0x40,0xd3,0x16,0x8d,0xd6,0x9f,0x4a,0x66 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ecb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("ECBMMT256-DECRYPT-2", "[ECB][MMT][256][DECRYPT][n2]") {
    const uint8_t KEY[] = { 0x0d,0x0e,0xc1,0xb6,0x1e,0xbc,0x51,0x77,0xc4,0x51,0x3e,0xf1,0xd7,0xd5,0xbb,0x97,0xd0,0x6a,0xba,0xa2,0xd3,0x37,0x10,0xa8,0xed,0xa6,0xd3,0x70,0x9a,0xcf,0x07,0x05 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0xf1,0x77,0x33,0xde,0x8f,0x76,0x31,0x10,0xef,0x4b,0x30,0x55,0x94,0x93,0x6c,0xa2,0xbb,0x75,0x11,0x9a,0xd6,0x52,0x61,0xbe,0x32,0xba,0x91,0x9a,0x2c,0x3e,0xf8,0xb8,0xf1,0xc4,0x2f,0x62,0xb8,0x47,0x43,0x62,0xe5,0x3e,0xe7,0xcc,0x6c,0x82,0xa6,0x47 };
    const uint8_t CIPHERTEXT[] = { 0xc1,0xc8,0x3f,0xa3,0xcd,0x3d,0x52,0x52,0x48,0x76,0xe7,0x15,0xbc,0x28,0xef,0xe7,0xc7,0xc4,0x25,0x6a,0x13,0x9e,0x9d,0x2c,0x87,0x4e,0xa0,0x29,0xbf,0x56,0xb7,0x92,0xba,0x06,0x06,0xcd,0xd3,0x9d,0xdb,0xbd,0xf3,0xb1,0x87,0x43,0x04,0xd1,0x6d,0x05 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ecb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("ECBMMT256-DECRYPT-3", "[ECB][MMT][256][DECRYPT][n3]") {
    const uint8_t KEY[] = { 0xae,0x67,0x99,0x9e,0xb2,0x40,0xa9,0xe5,0xb6,0xe3,0xf0,0xbd,0x6b,0x50,0x45,0x30,0x00,0x0b,0xe5,0x13,0x43,0xb8,0xbc,0x3b,0x0a,0xe8,0xe0,0xee,0xd1,0x33,0x5f,0x98 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x95,0x9b,0x7d,0x69,0x6e,0x22,0x67,0xf3,0xd4,0x65,0xf6,0xf7,0x7f,0xf2,0x45,0x32,0x96,0xcf,0xa5,0x48,0x43,0x36,0x39,0x81,0x48,0x48,0x53,0xe6,0x7c,0xc2,0x1d,0x34,0x0b,0x80,0x3d,0x6d,0x65,0x32,0x13,0xd1,0x03,0x7b,0x81,0xd8,0x49,0xc5,0xac,0xc3,0x61,0x77,0x1a,0x5a,0x07,0x2c,0x9c,0x29,0xd6,0xbc,0x50,0x96,0xc3,0x8c,0x9c,0x86 };
    const uint8_t CIPHERTEXT[] = { 0x25,0x4c,0x01,0x56,0x26,0xba,0xa3,0xed,0x2d,0x7f,0x05,0xf5,0xd0,0xa9,0x8c,0x8c,0xc2,0xf2,0x9d,0xd7,0xa4,0x41,0x0e,0xa4,0x1d,0x74,0xdb,0x4e,0x2c,0x5d,0x1b,0xe1,0xbd,0x0a,0x32,0x7f,0x7b,0x4a,0x47,0x03,0xe6,0x6c,0xf9,0xe3,0xa5,0x4a,0x4d,0x5b,0x1d,0x87,0xeb,0xc8,0x42,0x14,0x8b,0x52,0xad,0xf9,0xaa,0xcd,0xf0,0x52,0x81,0xe1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ecb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("ECBMMT256-DECRYPT-4", "[ECB][MMT][256][DECRYPT][n4]") {
    const uint8_t KEY[] = { 0xdd,0xe0,0x79,0x37,0x11,0x33,0xeb,0xd6,0x8d,0xf0,0x61,0xb5,0x6f,0x0e,0xfd,0x3a,0x14,0xc1,0x37,0xce,0xd3,0x5a,0x30,0xe0,0xeb,0x68,0x42,0x2c,0xb9,0x24,0xdc,0x3d };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x58,0x89,0xad,0x2c,0x09,0xa6,0x30,0x76,0x11,0xe6,0x11,0x5a,0x78,0xc1,0x35,0x66,0xde,0x05,0xb5,0x89,0x2f,0x78,0x50,0xfb,0x91,0x7f,0x83,0x89,0x8e,0x07,0x48,0x6c,0xc9,0xce,0x74,0x6e,0x89,0x1d,0xb1,0x02,0xa0,0xf5,0x70,0xd7,0xad,0x3c,0x28,0x04,0xf4,0x0c,0xdf,0xe2,0x3b,0xcc,0x8b,0x2c,0x8a,0x3b,0xfb,0xa4,0x86,0x32,0x89,0x2d,0x3d,0xf3,0xbb,0x7b,0xbd,0x10,0x29,0xb9,0x15,0xca,0xb2,0xfa,0xf2,0x81,0xc4,0xe6 };
    const uint8_t CIPHERTEXT[] = { 0xea,0x1f,0xd2,0xf0,0x64,0x54,0x89,0x06,0xad,0x10,0xce,0x12,0x40,0x75,0x88,0x68,0xed,0x9f,0xb3,0x29,0x21,0xda,0xbe,0x18,0x68,0x12,0x32,0xa8,0x30,0x8b,0x95,0x5a,0xd0,0xd2,0x8e,0x45,0xc9,0xf3,0x4a,0xf6,0x4b,0xec,0x1d,0x7b,0xfb,0x62,0x6d,0xbb,0xf3,0x93,0xcc,0x09,0x0a,0x8c,0x64,0xf8,0x56,0x9b,0x98,0x70,0xf0,0x08,0xe8,0x01,0xf7,0x00,0x15,0x78,0xd8,0xd2,0x86,0xb0,0xcc,0x5e,0xeb,0xab,0xa2,0xc9,0x20,0xe1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ecb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("ECBMMT256-DECRYPT-5", "[ECB][MMT][256][DECRYPT][n5]") {
    const uint8_t KEY[] = { 0xd6,0x8a,0x34,0x51,0x59,0x17,0x8b,0x9b,0xd2,0xe3,0xbd,0x7a,0x13,0xc9,0x51,0x2e,0xe9,0xb3,0x97,0x94,0x4e,0xff,0x81,0xa8,0xdf,0x28,0xb4,0x48,0x90,0xa2,0xdf,0x3b };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0xa5,0x6e,0x00,0x0b,0xe1,0x9e,0xce,0xd2,0x04,0x79,0xcb,0xe8,0x96,0x4f,0xdb,0x36,0x6c,0x43,0x7c,0xa3,0xb5,0xfd,0x9d,0x04,0xc3,0x39,0xc1,0xa5,0x1b,0xdb,0x0a,0xad,0x46,0xdf,0x1b,0x78,0xef,0x05,0xb0,0x2e,0x49,0x24,0x64,0x13,0x61,0x55,0xd7,0x6d,0xd3,0x2c,0x3b,0x4a,0xa4,0x19,0x8c,0x39,0x26,0xcb,0x75,0xd2,0x57,0x84,0x34,0xab,0x4f,0xff,0x08,0x94,0x50,0x8b,0x6f,0x60,0xff,0x39,0x68,0x6a,0x0f,0xd1,0x51,0xd1,0xbf,0xfb,0xa7,0xa7,0x86,0xb1,0xbc,0x02,0xac,0xd2,0xd2,0x3b,0x56,0xe4,0x57,0x49 };
    const uint8_t CIPHERTEXT[] = { 0x59,0x72,0x25,0x86,0xa5,0x6e,0xd6,0xc8,0x20,0x7d,0x6a,0x0a,0x9f,0x72,0x78,0x58,0x8f,0x52,0x03,0x78,0x2f,0xb6,0x4e,0x6f,0xfd,0x71,0xf1,0x48,0x6d,0x73,0x2d,0x10,0xe1,0xed,0x7d,0x25,0xd6,0xb6,0x6d,0xb1,0x5b,0xee,0xaf,0x71,0xc8,0xe1,0x6c,0xbb,0xac,0x2d,0xd8,0xbf,0x07,0x28,0x09,0x0d,0xba,0x7c,0x09,0x57,0x3b,0x14,0x2a,0x78,0x8d,0x3c,0x99,0xb6,0x70,0x03,0x36,0x44,0xd5,0xe4,0xa3,0x0b,0x94,0xa6,0x9b,0xab,0x61,0x81,0x86,0xbc,0xfd,0x82,0x4a,0x59,0xa9,0x31,0x63,0xdf,0xe0,0x70,0x36,0xf2 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ecb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("ECBMMT256-DECRYPT-6", "[ECB][MMT][256][DECRYPT][n6]") {
    const uint8_t KEY[] = { 0x5a,0x20,0xff,0x7d,0xa4,0x7c,0x7e,0x85,0x3b,0xec,0xca,0x0c,0xa5,0xf3,0x2b,0xc8,0x0e,0x17,0xde,0x97,0x33,0x37,0x14,0x6f,0x7e,0x1f,0x3c,0x93,0x72,0x5a,0x85,0x0d };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x34,0x46,0x7d,0x07,0xc2,0xe4,0x9c,0x44,0xe9,0x00,0x3d,0xa8,0x36,0x78,0x61,0x69,0xe7,0xc0,0xfb,0x54,0xf1,0xe2,0xf1,0x78,0x38,0x7c,0x2f,0x75,0x9d,0x50,0x80,0x9c,0xe8,0x4d,0x67,0x05,0xfe,0x63,0x50,0x90,0x7d,0x5e,0x94,0x5e,0x26,0x2a,0xf3,0x78,0x75,0x31,0x63,0xf5,0x56,0x9b,0xe9,0xc0,0x9c,0x87,0x4d,0x25,0x4d,0xde,0x25,0x45,0x89,0x8d,0x4c,0xbd,0x2e,0xaa,0x1a,0xde,0x9c,0x8a,0x02,0xf8,0xd7,0x6d,0x41,0x85,0x65,0xd0,0x20,0x75,0xe0,0x82,0x99,0x9b,0xbf,0x6f,0x2b,0xa9,0x85,0xf6,0x5f,0x17,0xc7,0x3c,0xc0,0xcc,0x29,0xac,0x04,0x82,0x4d,0xb9,0x8b,0x3c,0xc2,0xb7,0x71,0x26 };
    const uint8_t CIPHERTEXT[] = { 0xbe,0xd9,0xf2,0xdb,0x31,0xeb,0xbf,0xac,0x57,0xf3,0x74,0x5e,0x0d,0xac,0xf7,0x10,0x87,0xcb,0x35,0xc9,0x43,0x26,0xb9,0xba,0x3b,0x1b,0x7d,0xc3,0x5f,0x30,0x00,0x39,0x42,0xf7,0x98,0xe7,0x14,0x35,0x0a,0x52,0xd0,0x42,0x58,0x42,0xb6,0xb3,0xda,0x7d,0xfc,0x37,0x90,0xd6,0xc1,0xbf,0xb7,0x66,0x42,0xe2,0x9a,0x1a,0x50,0x7f,0xab,0x6e,0x02,0xa4,0xd2,0x77,0xa7,0xae,0x05,0x27,0xfe,0xb2,0x19,0xcd,0xaa,0x1c,0xd8,0xdb,0xe0,0x96,0x53,0xec,0x63,0x2c,0x7a,0x05,0xb2,0xad,0xe9,0x1b,0x7f,0x54,0x05,0xd6,0x64,0xa7,0x48,0x95,0xd2,0xa0,0xd9,0xb2,0x4a,0x0b,0x60,0x07,0xcf,0x2f,0x18,0xb1 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ecb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("ECBMMT256-DECRYPT-7", "[ECB][MMT][256][DECRYPT][n7]") {
    const uint8_t KEY[] = { 0x08,0x2d,0x33,0xed,0xd0,0xa1,0xad,0x3d,0xe5,0x96,0x76,0x2d,0x71,0x1b,0xae,0x6f,0x31,0x88,0xa1,0x2c,0x7b,0x6c,0xed,0x98,0x7f,0xc7,0xe8,0xc9,0xcd,0x7a,0x3c,0xc9 };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x51,0xc5,0x27,0xc0,0x98,0x53,0x69,0x23,0x4a,0x59,0x9f,0x47,0x67,0x31,0xe8,0xb5,0x1a,0xc7,0xa4,0x4b,0xfb,0xe3,0x7e,0xc7,0x1a,0x64,0x1a,0xd7,0x1a,0xd4,0x64,0xf9,0xe4,0x54,0x67,0xd8,0x2a,0x0d,0x10,0x1f,0x67,0x04,0x3b,0x87,0xe2,0xda,0x34,0xde,0x18,0x34,0x59,0x29,0x50,0x00,0xce,0xa9,0xe0,0xf0,0xcc,0xdd,0x82,0x27,0x0f,0xc7,0x0b,0x88,0x0f,0xa8,0x01,0x04,0xe0,0xb7,0x8b,0x7a,0x5b,0x16,0x20,0xde,0xe8,0x3d,0xa8,0x47,0x02,0x22,0x3b,0x27,0x7a,0x09,0x66,0xb1,0x0d,0xdf,0x44,0xef,0x06,0xb9,0x8e,0x48,0x78,0x80,0x92,0xc7,0x63,0x89,0x5d,0x95,0xf1,0x3f,0xd3,0x89,0xff,0xf5,0x70,0x6e,0x70,0x87,0x6d,0x5a,0xf8,0xc1,0x97,0xcd,0xeb,0xb3,0x8a,0x4d,0x2b,0xa6 };
    const uint8_t CIPHERTEXT[] = { 0x49,0x65,0x53,0xf2,0x4d,0x47,0x26,0x4e,0xf7,0x4a,0x58,0x4b,0x89,0x3c,0xcd,0x4e,0xa1,0xcf,0xc0,0xb1,0x04,0x4a,0xac,0x15,0x99,0x7e,0x6d,0xfa,0xb9,0xfc,0xa2,0x8d,0xa6,0x85,0x57,0xc0,0x58,0xc2,0xe1,0xa0,0x80,0x35,0x08,0xe4,0xc7,0x70,0x6c,0xc1,0x56,0x85,0x21,0x06,0x9c,0xbd,0x9d,0x64,0x4b,0x8d,0xd4,0x0d,0xa4,0xc5,0xa1,0x82,0xf5,0x0b,0x68,0xa5,0x60,0x88,0xfa,0x16,0xdd,0xe1,0xb8,0xbc,0x82,0x69,0xfc,0xa2,0x03,0x95,0xb4,0x05,0x75,0xb0,0x50,0xab,0x57,0xcf,0xdf,0x76,0xd2,0x08,0x74,0x38,0x40,0xdf,0xcf,0xc9,0xec,0x01,0x39,0x57,0x18,0x35,0xb0,0xfe,0x45,0x8f,0x44,0x98,0xae,0xe6,0xc1,0xd7,0x16,0x89,0x8e,0x91,0xc3,0x2e,0xd5,0x5a,0xcb,0x2b,0xe4,0x58 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ecb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("ECBMMT256-DECRYPT-8", "[ECB][MMT][256][DECRYPT][n8]") {
    const uint8_t KEY[] = { 0x3e,0x19,0x34,0x55,0x49,0x52,0xb8,0x7a,0x07,0xd6,0x37,0x17,0x21,0xf4,0xd7,0x8a,0x0e,0x9a,0xda,0xdc,0x42,0xbe,0x73,0x47,0xa2,0xfc,0xd8,0xf5,0x3c,0x81,0x99,0x0b };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x5f,0x96,0x7e,0x10,0xda,0x68,0x88,0x75,0x67,0xb5,0x14,0x29,0x31,0x49,0x69,0x72,0x12,0x88,0x8e,0xfc,0x9f,0xd9,0x06,0x04,0x45,0x9f,0x8a,0x9c,0x4f,0xa1,0xf4,0x11,0x7f,0x02,0x14,0xfa,0x67,0x5b,0x68,0x05,0x71,0xbd,0x98,0x0c,0xf9,0x41,0xbf,0xcc,0xd4,0x82,0x6e,0x1f,0xe1,0x42,0x0a,0x0b,0xa5,0x95,0x54,0x34,0x1b,0x50,0x7e,0x76,0x0d,0x2d,0x85,0xc7,0x21,0x9b,0x3f,0x5e,0x26,0x1e,0xef,0x2d,0x20,0x1b,0xc1,0x34,0xd2,0xec,0x32,0xd8,0xb9,0x71,0x57,0xe3,0xde,0x91,0xf1,0xc3,0x12,0xb2,0x6f,0xf1,0x93,0xe6,0x37,0xbf,0x78,0x01,0x28,0x50,0xf2,0x3d,0x05,0x36,0x71,0x5e,0x51,0xa6,0x8b,0xe7,0x30,0xc5,0x53,0x75,0x77,0x46,0x42,0x34,0x5e,0x0d,0xaa,0xa4,0xc4,0x01,0x85,0x98,0x5c,0xab,0x38,0xdf,0x09,0xda,0xc9,0xa6,0x88,0xe6,0xb5,0x97,0xd3,0x27 };
    const uint8_t CIPHERTEXT[] = { 0x2b,0x3c,0x03,0x6b,0xe6,0x8f,0xba,0x7a,0x62,0x5d,0xc7,0x2a,0x0e,0x68,0xb6,0x67,0x73,0x26,0xf8,0x75,0x17,0x14,0xe0,0xe1,0xa1,0x4d,0xf2,0xb7,0x3d,0x5b,0x5d,0xf5,0x42,0x4d,0xc6,0x40,0x13,0x09,0x47,0xd6,0x43,0xe4,0xb8,0xc4,0xfc,0x70,0x2d,0x59,0xa1,0x95,0xbf,0xda,0xb2,0xe4,0x90,0x77,0xf0,0x27,0x09,0x7e,0xc2,0x3d,0x66,0xcf,0xd8,0x25,0x75,0x90,0x0e,0x58,0x9a,0x21,0x93,0x5c,0x17,0x52,0x4a,0x96,0x8a,0xd4,0x70,0x60,0xb7,0xee,0x80,0x5b,0x88,0x71,0x53,0x06,0x52,0xee,0x8c,0x90,0x5a,0x26,0x33,0xeb,0x98,0xc2,0xa0,0x22,0xbb,0x45,0x9b,0xec,0x6d,0x3e,0xc1,0x81,0xd7,0xc2,0x2a,0xac,0x68,0x19,0x48,0x22,0xd2,0xb8,0x12,0x12,0x56,0x6f,0x62,0xfd,0x42,0xe4,0x9c,0xc8,0xb8,0x40,0x91,0x10,0xb0,0x28,0xa3,0xbd,0x40,0xef,0x29,0xda,0x1c,0x0a };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ecb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

TEST_CASE("ECBMMT256-DECRYPT-9", "[ECB][MMT][256][DECRYPT][n9]") {
    const uint8_t KEY[] = { 0xc4,0xa7,0x1e,0x05,0x5a,0x72,0x54,0xdd,0xa3,0x60,0x69,0x3f,0xe1,0xbe,0x49,0xf1,0x0f,0xaa,0x67,0x31,0xc3,0x6d,0xba,0xa6,0x59,0x0b,0x05,0x97,0x4e,0x18,0x5c,0x5b };
    const uint8_t IV[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    const uint8_t PLAINTEXT[] = { 0x31,0xfd,0x5a,0x30,0x7e,0x27,0x9b,0x2f,0x34,0x58,0x1e,0x2c,0x43,0x23,0x79,0xdf,0x8e,0xcc,0xba,0xf7,0x95,0x32,0x93,0x89,0x16,0x71,0x1c,0xd3,0x77,0x54,0x0b,0x90,0x45,0x37,0x3e,0x47,0xf2,0x21,0x4b,0x8f,0x87,0x60,0x40,0xaf,0x73,0x3f,0x6c,0x9d,0x8f,0x03,0xa7,0xc5,0x8f,0x87,0x14,0xd2,0xfb,0xb4,0xc1,0x4a,0xf5,0x9c,0x75,0xb4,0x83,0xad,0xc7,0x18,0x94,0x6e,0xe9,0x07,0xa1,0x82,0x86,0xcc,0x4e,0xfd,0x20,0x67,0x89,0x06,0x4b,0x6f,0x1b,0x19,0x5f,0x0d,0x0d,0x23,0x44,0x68,0xe4,0xf0,0x0e,0x6f,0x1c,0xad,0x5c,0xd3,0xb9,0xc0,0xa6,0x43,0xb3,0xc0,0xdd,0x09,0x28,0x0f,0xf2,0xe2,0xa5,0x92,0x91,0x83,0x40,0x93,0x84,0xdd,0x72,0xdc,0x94,0xe3,0x96,0x87,0xea,0x2b,0x62,0x3d,0x5d,0x77,0x67,0x00,0xbd,0x8b,0x36,0xe6,0x13,0x0f,0xfd,0xe9,0x66,0xf1,0x34,0xc4,0xb1,0xf3,0x5f,0x29,0xc5,0xcc,0x4a,0x03,0x29,0x7e,0x1c,0xcc,0x95,0x39 };
    const uint8_t CIPHERTEXT[] = { 0x2c,0x48,0x7f,0xa9,0x6f,0x40,0x90,0xc5,0x6a,0xa1,0xb5,0xbe,0x81,0x91,0x8a,0x93,0x4c,0x94,0x92,0x87,0x8f,0xb0,0xcd,0x68,0x6d,0xcf,0x8d,0x17,0xd8,0x64,0x85,0x45,0x4c,0x51,0x23,0x7b,0xbd,0x09,0x20,0x5d,0xce,0xf1,0x55,0x2f,0x43,0x0d,0xd0,0x98,0xb9,0xd8,0x27,0xa6,0x94,0x73,0x0c,0x13,0x3a,0x02,0x22,0xc7,0x7f,0x54,0x0f,0x9d,0x5f,0xc2,0xd3,0x6a,0xf3,0x59,0x58,0x3c,0x9e,0x3b,0x49,0xdf,0x88,0x42,0x28,0xa6,0x4d,0xe7,0x9b,0x67,0xf6,0x62,0x07,0xc8,0x28,0x13,0x60,0xb9,0x9b,0x21,0x40,0x42,0xce,0x61,0x36,0x7f,0xf9,0x79,0x60,0xe9,0x44,0x45,0x3c,0xd6,0x36,0x79,0xbb,0x44,0x70,0x88,0x97,0xd2,0x9b,0xc5,0xe7,0x0f,0x9f,0xc8,0xf1,0xf7,0x15,0x14,0x3f,0xbb,0x00,0xf7,0xf5,0xc1,0xb7,0xb1,0x61,0xec,0x26,0xd8,0xd4,0x1d,0x36,0xfa,0xb0,0xfa,0x8a,0x85,0xc3,0xee,0x6c,0xe4,0xd3,0x70,0x07,0xeb,0x7a,0x89,0xd6,0x75,0x35,0x90 };
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_decrypt_ecb(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

