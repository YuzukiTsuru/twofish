# Twofish C++ Implementation

This repository contains a C++ implementation of the Twofish encryption algorithm.

## Overview

Twofish is a symmetric key block cipher designed by Bruce Schneier and colleagues, which was a candidate algorithm in the Advanced Encryption Standard (AES) competition.

This implementation provides a modern C++ implementation of the algorithm, offering:
- Object-oriented design
- Support for 128-bit, 192-bit, and 256-bit keys
- Efficient encryption and decryption operations
- Clean API for ease of use
- Detailed Doxygen documentation

## Building the Project

The project uses CMake as its build system. To build the project:

1. Ensure you have CMake 3.11 or later installed
2. Open a terminal and navigate to the project directory
3. Create a build directory:
   ```
   mkdir build
   cd build
   ```
4. Run CMake to configure the project:
   ```
   cmake ..
   ```
5. Build the project:
   ```
   cmake --build .
   ```

This will build:
- The Twofish library
- The test executable

## Using the C++ Implementation

### Including the Library

To use the C++ implementation in your project, include the header file:

```cpp
#include "twofish.hpp"
```

### Basic Usage

Here's a simple example demonstrating how to use the C++ Twofish implementation:

```cpp
#include <iostream>
#include <array>
#include <vector>
#include <cstdint>
#include "twofish.hpp"

int main() {
    // Create a Twofish cipher instance
    Twofish cipher;
    
    // Define a 256-bit key (8 words of 4 bytes each)
    std::array<uint32_t, 8> key = {
        0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff,
        0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff
    };
    
    // Initialize the cipher with the key
    cipher.initialize(key, 256);  // 256-bit key
    
    // Define a plaintext block (16 bytes, 4 words)
    std::array<uint32_t, 4> plaintext = {
        0x01234567, 0x89abcdef, 0x01234567, 0x89abcdef
    };
    
    // Encrypt the plaintext
    std::array<uint32_t, 4> ciphertext = {0};
    cipher.encrypt(plaintext, ciphertext);
    
    // Decrypt the ciphertext
    std::array<uint32_t, 4> decrypted = {0};
    cipher.decrypt(ciphertext, decrypted);
    
    return 0;
}
```

### Alternative Usage with Byte Arrays

The implementation also supports direct byte array encryption and decryption:

```cpp
#include <iostream>
#include <array>
#include <cstdint>
#include "twofish.hpp"

int main() {
    // Create a Twofish cipher instance
    Twofish cipher;
    
    // Define a 128-bit key (16 bytes)
    std::array<uint8_t, 16> key = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    
    // Initialize the cipher with the key
    cipher.initialize(key.data(), 128);  // 128-bit key
    
    // Define a plaintext block (16 bytes)
    std::array<uint8_t, 16> plaintext = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    // Encrypt the plaintext
    std::array<uint8_t, 16> ciphertext = {0};
    cipher.encrypt(plaintext.data(), ciphertext.data());
    
    // Decrypt the ciphertext
    std::array<uint8_t, 16> decrypted = {0};
    cipher.decrypt(ciphertext.data(), decrypted.data());
    
    return 0;
}
```

### Supported Key Sizes

The implementation supports three key sizes:
- 128-bit (4 words or 16 bytes) - pass 128 as the second argument to `initialize`
- 192-bit (6 words or 24 bytes) - pass 192 as the second argument to `initialize`
- 256-bit (8 words or 32 bytes) - pass 256 as the second argument to `initialize`

## Testing

The project includes a test executable (`twofish_ctest`) that demonstrates the encryption and decryption operations with different key sizes.

To run the test:
1. Build the project as described above
2. Run the test executable from the build directory:
   ```
   ./twofish_ctest
   ```
   