# osslCryptoPki Implementation Summary

## Overview

A complete **PKI encryption/decryption class (`osslCryptoPki`)** has been developed for the osslCryptoLibrary. The implementation provides all-static methods for RSA and ECC encryption/decryption using OpenSSL 3.x.

---

## What Was Built

### New Files Created

| File | Purpose |
|------|---------|
| `osslCryptoPki.h` | All-static class declaration with complete API |
| `osslCryptoPki.cpp` | Full implementation (~600 lines) |
| `crypto_demo.cpp` | Test executable with round-trip validation |

### Modified Files

| File | Changes |
|------|---------|
| `CMakeLists.txt` | Added osslCryptoPki.cpp to library; added crypto_demo executable target |
| `.vscode/launch.json` | Added debug configurations for crypto_demo (RSA and ECC test cases) |

---

## Class API: osslCryptoPki

All methods are `static`. Class is never instantiated.

### RSA Encryption (RSA-OAEP-SHA256)

```cpp
static std::vector<unsigned char> rsaEncrypt(
    const osslCertificate& cert,
    const std::vector<unsigned char>& plaintext);

static std::vector<unsigned char> rsaDecrypt(
    const std::string& privKeyPem,
    const std::vector<unsigned char>& ciphertext);
```

**Details:**
- Uses RSA-OAEP padding with SHA-256 for both hash and MGF1
- Plaintext size limited by `(keyBits/8) - 66` bytes (for 2048-bit RSA: ~190 bytes max)
- Ciphertext size equals RSA modulus size

### ECC Encryption (ECIES)

```cpp
static std::vector<unsigned char> eccEncrypt(
    const osslCertificate& cert,
    const std::vector<unsigned char>& plaintext);

static std::vector<unsigned char> eccDecrypt(
    const std::string& privKeyPem,
    const std::vector<unsigned char>& ciphertext);
```

**Details:**
- Ephemeral ECDH key generation on same curve as recipient public key
- Shared secret derivation via ECDH
- AES-256-GCM encryption with HKDF-SHA256 key derivation
- Self-describing ciphertext format (see below)

### Generic API (Auto-Detect)

```cpp
static std::vector<unsigned char> pkiEncrypt(
    const osslCertificate& cert,
    const std::vector<unsigned char>& plaintext);

static std::vector<unsigned char> pkiDecrypt(
    const std::string& privKeyPem,
    const std::vector<unsigned char>& ciphertext);
```

- Automatically detects RSA vs EC from certificate/private key type
- Dispatches to appropriate encrypt/decrypt method
- Simplifies API for code that handles mixed key types

### String Convenience Overloads

```cpp
static std::vector<unsigned char> pkiEncrypt(
    const osslCertificate& cert,
    const std::string& plaintext);

static std::string pkiDecryptToString(
    const std::string& privKeyPem,
    const std::vector<unsigned char>& ciphertext);
```

---

## ECIES Ciphertext Binary Format

The ECIES ciphertext is self-describing, allowing decryption without external metadata.

### Layout

```
Offset  Len  Field          Value/Description
------  ---  -----          ------------------
0       4    magic          0x4F 0x43 0x52 0x59 ("OCRY")
4       1    version        0x01
5       1    flags          0x00 (reserved)
6       2    pubkey_len     big-endian uint16 (ephemeral public key length)
8       N    ephemeral_pub  DER SubjectPublicKeyInfo (uncompressed EC point)
8+N     12   iv             AES-256-GCM nonce (random, 12 bytes)
8+N+12  16   tag            AES-256-GCM authentication tag
8+N+28  4    ct_len         big-endian uint32 (ciphertext length)
8+N+32  M    ciphertext     AES-256-GCM encrypted payload
```

### Size Examples

- **P-256 (256-bit)**: ephemeral pubkey = 91 bytes → total overhead = 123 bytes
- **P-384 (384-bit)**: ephemeral pubkey = 120 bytes → total overhead = 152 bytes
- **P-521 (521-bit)**: ephemeral pubkey = 158 bytes → total overhead = 190 bytes

---

## Test Results

All tests pass successfully:

### RSA Testing
- ✅ RSA-2048-SHA256: Generic and RSA-specific encryption/decryption
- ✅ RSA-3072-SHA256: Full round-trip validation
- ✅ RSA-4096-SHA256: All three key sizes verified

### ECC Testing
- ✅ EC P-256 (prime256v1): ECIES encryption/decryption
- ✅ EC P-384 (secp384r1): ECIES encryption/decryption
- ✅ EC P-521 (secp521r1): ECIES encryption/decryption

### Test Coverage
- Generic `pkiEncrypt()` / `pkiDecrypt()` round-trip
- String convenience overload round-trip
- Algorithm-specific method round-trip
- Plaintext recovery and validation

---

## Implementation Details

### Error Handling

All errors throw `std::runtime_error` with descriptive messages and OpenSSL error context:

```cpp
throw std::runtime_error("operation failed: " + sslError());
```

### Memory Management

- All `EVP_PKEY*` and `EVP_PKEY_CTX*` objects properly freed
- `BIO*` objects allocated with `BIO_new_mem_buf()` and freed with `BIO_free()`
- `std::vector` used for buffer ownership
- OpenSSL reference counting respected for X509 certificates

### HKDF-SHA256 Implementation

Implemented manually via HMAC-SHA256 (RFC 5869) for maximum portability:

1. **Extract**: `PRK = HMAC-SHA256(salt, IKM)` where salt defaults to 32 zero bytes if empty
2. **Expand**: Generate output blocks `T(i) = HMAC-SHA256(PRK, T(i-1) || info || counter)`

Benefits:
- No dependency on OpenSSL's EVP_KDF API version quirks
- Full RFC 5869 compliance
- Works consistently across OpenSSL 3.x distributions

### Supported Algorithms

**RSA:**
- Padding: OAEP with SHA-256
- Key sizes: 2048, 3072, 4096 bits (and larger)
- Ciphertext is raw EVP_PKEY_encrypt output

**ECC:**
- Curves: Any NIST curve (P-256, P-384, P-521, etc.)
- ECDH: Ephemeral key on same curve as recipient
- Symmetric encryption: AES-256-GCM
- Key derivation: HKDF-SHA256 with salt = (ephemeral_pubkey_der || iv)

---

## Usage Examples

### RSA Encryption/Decryption

```cpp
#include "osslCertificate.h"
#include "osslCryptoPki.h"

osslCertificate cert = osslCertificate::fromFile("rsa_cert.pem");
std::string privKeyPem = readFile("rsa_key.pem");

std::vector<unsigned char> plaintext{...};

// Encrypt with public key
auto ciphertext = osslCryptoPki::rsaEncrypt(cert, plaintext);

// Decrypt with private key
auto recovered = osslCryptoPki::rsaDecrypt(privKeyPem, ciphertext);
assert(recovered == plaintext);
```

### ECC Encryption/Decryption

```cpp
osslCertificate cert = osslCertificate::fromFile("ec_cert.pem");
std::string privKeyPem = readFile("ec_key.pem");

std::vector<unsigned char> plaintext{...};

// ECIES encrypt
auto ciphertext = osslCryptoPki::eccEncrypt(cert, plaintext);

// ECIES decrypt
auto recovered = osslCryptoPki::eccDecrypt(privKeyPem, ciphertext);
assert(recovered == plaintext);
```

### Generic API (Mixed Key Types)

```cpp
// Works with any RSA or EC certificate
std::vector<unsigned char> ciphertext = osslCryptoPki::pkiEncrypt(cert, plaintext);

// Automatically detects key type from private key
std::vector<unsigned char> plaintext = osslCryptoPki::pkiDecrypt(privKeyPem, ciphertext);
```

### String Convenience Overloads

```cpp
std::string message = "Hello, World!";

// Encrypt string directly
auto ciphertext = osslCryptoPki::pkiEncrypt(cert, message);

// Decrypt to string
std::string decrypted = osslCryptoPki::pkiDecryptToString(privKeyPem, ciphertext);
assert(decrypted == message);
```

---

## Debugging in VS Code

Two debug configurations have been added to `.vscode/launch.json`:

1. **Debug crypto_demo (RSA)** — Runs test against RSA-2048 certificate
2. **Debug crypto_demo (ECC)** — Runs test against EC P-256 certificate

To debug:
1. Open VS Code
2. Go to Run → Start Debugging (F5)
3. Select the desired configuration from the dropdown
4. Set breakpoints and step through the code

---

## Building

```bash
cd /media/sf_Shared/osslCryptoLibrary/build
cmake ..
make
```

New executable: `./crypto_demo`

---

## Testing

Run demo with different certificates:

```bash
# RSA tests
./build/crypto_demo test_certs/rsa2048_sha256.pem test_certs/rsa2048_sha256.key
./build/crypto_demo test_certs/rsa4096_sha256.pem test_certs/rsa4096_sha256.key

# ECC tests
./build/crypto_demo test_certs/ec_prime256v1_sha256.pem test_certs/ec_prime256v1_sha256.key
./build/crypto_demo test_certs/ec_secp384r1_sha256.pem test_certs/ec_secp384r1_sha256.key
./build/crypto_demo test_certs/ec_secp521r1_sha256.pem test_certs/ec_secp521r1_sha256.key
```

Expected output: `All Tests Passed ✓`

---

## Technical Notes

### OpenSSL APIs Used

- **RSA**: `EVP_PKEY_encrypt`, `EVP_PKEY_decrypt` with `EVP_PKEY_CTX`
- **ECDH**: `EVP_PKEY_derive` with peer public key
- **AES-GCM**: `EVP_CIPHER_CTX`, `EVP_EncryptInit_ex`, `EVP_EncryptFinal_ex`, `EVP_CTRL_GCM_*`
- **HMAC**: `HMAC_CTX`, `HMAC_Init_ex`, `HMAC_Update`, `HMAC_Final` for HKDF implementation
- **Random**: `RAND_bytes` for IV generation
- **Key loading**: `PEM_read_bio_PrivateKey`, `d2i_PUBKEY` for DER parsing

### Limitations & Considerations

- Private keys must be in unencrypted PEM format (encrypted key support can be added via password callback)
- RSA plaintext size is limited by OAEP padding requirements (~190 bytes for 2048-bit keys)
- ECIES ciphertexts are larger due to ephemeral key inclusion (but self-contained and reproducible)
- All operations throw `std::runtime_error` on failure — caller must handle exceptions

### Performance Notes

- RSA encryption/decryption speed depends on key size
- ECC ECIES requires ephemeral key generation (100-200 microseconds typical)
- AES-256-GCM encryption is fast (microseconds per MB on modern CPU)
- Overall: suitable for one-off encryption; batch operations should minimize key loads

---

## Files Summary

```
osslCryptoLibrary/
├── osslCryptoPki.h              [NEW] Header with class declaration
├── osslCryptoPki.cpp            [NEW] Implementation (~600 lines)
├── crypto_demo.cpp              [NEW] Test executable
├── CMakeLists.txt               [MODIFIED] Added osslCryptoPki.cpp and crypto_demo target
├── .vscode/launch.json          [MODIFIED] Added debug configurations
├── osslCertificate.h            (existing)
├── osslCertificate.cpp          (existing)
├── test_certs/                  (existing test certificates)
└── ...
```

---

## Verification Checklist

- [x] Header file compiles without errors
- [x] Implementation compiles and links
- [x] All test certificates load successfully
- [x] RSA-2048 encryption/decryption works
- [x] RSA-4096 encryption/decryption works
- [x] ECC P-256 ECIES encryption/decryption works
- [x] ECC P-384 ECIES encryption/decryption works
- [x] ECC P-521 ECIES encryption/decryption works
- [x] Generic `pkiEncrypt()` / `pkiDecrypt()` auto-detection works
- [x] String convenience overloads work
- [x] Ciphertext round-trip produces original plaintext
- [x] VS Code debug configuration works
- [x] Error handling and exceptions work correctly

---

**Implementation Date:** 2026-03-25
**Status:** ✅ Complete and tested
**Ready for:** Integration, further development, debugging
