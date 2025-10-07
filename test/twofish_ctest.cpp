#include <iostream>
#include <iomanip>
#include <array>
#include <vector>
#include <cassert>

#include "twofish.hpp"

// Helper function to print a 16-byte block in hexadecimal (uint8_t version)
void print_block(const std::array<uint8_t, 16> &block, const std::string &label) {
    std::cout << label << std::hex << std::setfill('0');
    for (const auto &byte: block) {
        std::cout << " " << std::setw(2) << static_cast<int>(byte);
    }
    std::cout << std::dec << std::setfill(' ') << std::endl;
}

// Helper function to print a key in hexadecimal (uint8_t version)
void print_key(const std::vector<uint8_t> &key, const std::string &label) {
    std::cout << label << std::hex << std::setfill('0');
    for (const auto &byte: key) {
        std::cout << " " << std::setw(2) << static_cast<int>(byte);
    }
    std::cout << std::dec << std::setfill(' ') << std::endl;
}

// Test case 1: 128-bit key
void test_twofish_128bit_key() {
    Twofish cipher;

    // 128-bit key (16 bytes)
    const std::vector<uint8_t> key = {
        0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32,
        0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A
    };

    // Test block
    constexpr std::array<uint8_t, 16> plaintext = {
        0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E,
        0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19
    };

    constexpr std::array<uint8_t, 16> verify_ciphertext = {
        0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85,
        0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3
    };

    std::array<uint8_t, 16> ciphertext = {0};
    std::array<uint8_t, 16> decrypted = {0};

    // Initialize cipher with key
    cipher.initialize(key, 128);

    // Print test information
    std::cout << "\nTest Case 1: 128-bit Key" << std::endl;
    print_key(key, "Key:");
    print_block(plaintext, "Plaintext:");

    // Encrypt
    cipher.encrypt(plaintext, ciphertext);
    print_block(ciphertext, "Ciphertext:");
    print_block(verify_ciphertext, "Verify Ciphertext:");
    assert(ciphertext == verify_ciphertext && "Encryption failed for 128-bit key");
    std::cout << "Encryption successful" << std::endl;

    // Decrypt
    cipher.decrypt(ciphertext, decrypted);
    print_block(decrypted, "Decrypted:");

    // Verify decryption matches plaintext
    assert(plaintext == decrypted && "Decryption failed for 128-bit key");
    std::cout << "Decryption successful" << std::endl;
}

// Test case 2: 192-bit key
void test_twofish_192bit_key() {
    Twofish cipher;

    // 192-bit key (24 bytes)
    const std::vector<uint8_t> key = {
        0x88, 0xB2, 0xB2, 0x70, 0x6B, 0x10, 0x5E, 0x36,
        0xB4, 0x46, 0xBB, 0x6D, 0x73, 0x1A, 0x1E, 0x88,
        0xEF, 0xA7, 0x1F, 0x78, 0x89, 0x65, 0xBD, 0x44
    };

    // Test block
    constexpr std::array<uint8_t, 16> plaintext = {
        0x39, 0xDA, 0x69, 0xD6, 0xBA, 0x49, 0x97, 0xD5,
        0x85, 0xB6, 0xDC, 0x07, 0x3C, 0xA3, 0x41, 0xB2
    };
    
    constexpr std::array<uint8_t, 16> verify_ciphertext = {
        0x18, 0x2B, 0x02, 0xD8, 0x14, 0x97, 0xEA, 0x45,
        0xF9, 0xDA, 0xAC, 0xDC, 0x29, 0x19, 0x3A, 0x65
    };

    std::array<uint8_t, 16> ciphertext = {0};
    std::array<uint8_t, 16> decrypted = {0};

    // Initialize cipher with key
    cipher.initialize(key, 192);

    // Print test information
    std::cout << "\nTest Case 2: 192-bit Key" << std::endl;
    print_key(key, "Key:");
    print_block(plaintext, "Plaintext:");

    // Encrypt
    cipher.encrypt(plaintext, ciphertext);
    print_block(ciphertext, "Ciphertext:");
    print_block(verify_ciphertext, "Verify Ciphertext:");
    assert(ciphertext == verify_ciphertext && "Encryption failed for 192-bit key");
    std::cout << "Encryption successful" << std::endl;

    // Decrypt
    cipher.decrypt(ciphertext, decrypted);
    print_block(decrypted, "Decrypted:");

    // Verify decryption matches plaintext
    assert(plaintext == decrypted && "Decryption failed for 192-bit key");
    std::cout << "Decryption successful" << std::endl;
}

// Test case 3: 256-bit key
void test_twofish_256bit_key() {
    Twofish cipher;

    // 256-bit key (32 bytes)
    const std::vector<uint8_t> key = {
        0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46,
        0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
        0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
        0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
    };

    // Test block
    constexpr std::array<uint8_t, 16> plaintext = {
        0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F,
        0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6
    };
    
    constexpr std::array<uint8_t, 16> verify_ciphertext = {
        0x6C, 0xB4, 0x56, 0x1C, 0x40, 0xBF, 0x0A, 0x97,
        0x05, 0x93, 0x1C, 0xB6, 0xD4, 0x08, 0xE7, 0xFA
    };

    std::array<uint8_t, 16> ciphertext = {0};
    std::array<uint8_t, 16> decrypted = {0};

    // Initialize cipher with key
    cipher.initialize(key, 256);

    // Print test information
    std::cout << "\nTest Case 3: 256-bit Key with non-zero plaintext" << std::endl;
    print_key(key, "Key:");
    print_block(plaintext, "Plaintext:");

    // Encrypt
    cipher.encrypt(plaintext, ciphertext);
    print_block(ciphertext, "Ciphertext:");
    print_block(verify_ciphertext, "Verify Ciphertext:");
    assert(ciphertext == verify_ciphertext && "Encryption failed for 256-bit key");
    std::cout << "Encryption successful" << std::endl;

    // Decrypt
    cipher.decrypt(ciphertext, decrypted);
    print_block(decrypted, "Decrypted:");

    // Verify decryption matches plaintext
    assert(plaintext == decrypted && "Decryption failed for 256-bit key");
    std::cout << "Decryption successful" << std::endl;
}

// Register tests with CTest
int main(int argc, char** argv) {
    std::cout << "Testing Twofish implementation with CTest..." << std::endl;
    
    // Run tests
    test_twofish_128bit_key();
    test_twofish_192bit_key();
    test_twofish_256bit_key();
    
    std::cout << "\nAll tests completed successfully!" << std::endl;
    return 0;
}