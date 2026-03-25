#include "osslCryptoPki.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>

#include <cstring>
#include <sstream>
#include <iomanip>

// ============================================================
// Helper: error reporting
// ============================================================

std::string osslCryptoPki::sslError()
{
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

// ============================================================
// Helper: Load private key from PEM string
// ============================================================

EVP_PKEY* osslCryptoPki::loadPrivateKey(const std::string& pem)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio)
        throw std::runtime_error("BIO_new_mem_buf failed: " + sslError());

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey)
        throw std::runtime_error("PEM_read_bio_PrivateKey failed: " + sslError());

    return pkey;  // caller owns, must EVP_PKEY_free
}

// ============================================================
// Helper: HKDF-SHA256
// ============================================================

std::vector<unsigned char> osslCryptoPki::hkdfSha256(
    const std::vector<unsigned char>& sharedSecret,
    const std::vector<unsigned char>& salt,
    const std::string&                info,
    size_t                            outputLen)
{
    // HKDF-SHA256 implementation per RFC 5869
    // Step 1: Extract
    unsigned char prk[32];  // PRK is 32 bytes for SHA256
    unsigned int prkLen = 32;

    // If salt is empty, use a salt of zeros (length of hash = 32 for SHA256)
    std::vector<unsigned char> actualSalt = salt;
    if (actualSalt.empty())
        actualSalt.resize(32, 0x00);

    if (HMAC(EVP_sha256(),
             actualSalt.data(), static_cast<int>(actualSalt.size()),
             sharedSecret.data(), static_cast<int>(sharedSecret.size()),
             prk, &prkLen) == nullptr)
        throw std::runtime_error("HKDF extract (HMAC) failed: " + sslError());

    // Step 2: Expand
    std::vector<unsigned char> out;
    unsigned char t[32];  // T(i-1) from RFC 5869
    unsigned int tLen = 0;
    unsigned int counter = 1;

    while (out.size() < outputLen)
    {
        // T(i) = HMAC-Hash(PRK, T(i-1) | info | counter)
        HMAC_CTX* ctx = HMAC_CTX_new();
        if (!ctx)
            throw std::runtime_error("HMAC_CTX_new failed: " + sslError());

        if (HMAC_Init_ex(ctx, prk, 32, EVP_sha256(), nullptr) != 1)
        {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("HMAC_Init_ex failed: " + sslError());
        }

        // Update with T(i-1)
        if (tLen > 0 && HMAC_Update(ctx, t, tLen) != 1)
        {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("HMAC_Update (T) failed: " + sslError());
        }

        // Update with info
        if (HMAC_Update(ctx, reinterpret_cast<const unsigned char*>(info.c_str()),
                       static_cast<int>(info.size())) != 1)
        {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("HMAC_Update (info) failed: " + sslError());
        }

        // Update with counter
        unsigned char counterByte = static_cast<unsigned char>(counter);
        if (HMAC_Update(ctx, &counterByte, 1) != 1)
        {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("HMAC_Update (counter) failed: " + sslError());
        }

        // Finalize to get T(i)
        if (HMAC_Final(ctx, t, &tLen) != 1)
        {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("HMAC_Final failed: " + sslError());
        }
        HMAC_CTX_free(ctx);

        // Append T(i) to output
        out.insert(out.end(), t, t + tLen);
        counter++;
    }

    // Return only the requested number of bytes
    out.resize(outputLen);
    return out;
}

// ============================================================
// Helper: ECDH shared secret derivation
// ============================================================

std::vector<unsigned char> osslCryptoPki::ecdhDeriveShared(
    EVP_PKEY* ourKey,
    EVP_PKEY* peerKey)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(ourKey, nullptr);
    if (!ctx)
        throw std::runtime_error("EVP_PKEY_CTX_new failed: " + sslError());

    if (EVP_PKEY_derive_init(ctx) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_derive_init failed: " + sslError());
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerKey) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_derive_set_peer failed: " + sslError());
    }

    size_t sharedLen = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &sharedLen) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_derive (size) failed: " + sslError());
    }

    std::vector<unsigned char> shared(sharedLen);
    if (EVP_PKEY_derive(ctx, shared.data(), &sharedLen) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_derive (final) failed: " + sslError());
    }

    shared.resize(sharedLen);
    EVP_PKEY_CTX_free(ctx);
    return shared;
}

// ============================================================
// Helper: AES-256-GCM encrypt
// ============================================================

std::vector<unsigned char> osslCryptoPki::aesGcmEncrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& plaintext,
    std::vector<unsigned char>&       tagOut)
{
    if (key.size() != 32)
        throw std::runtime_error("AES-256-GCM key must be 32 bytes");
    if (iv.size() != 12)
        throw std::runtime_error("AES-256-GCM IV must be 12 bytes");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed: " + sslError());

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed: " + sslError());
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed: " + sslError());
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex (key+iv) failed: " + sslError());
    }

    std::vector<unsigned char> ct(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int len = 0;
    if (EVP_EncryptUpdate(ctx, ct.data(), &len, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed: " + sslError());
    }

    int cipherLen = len;
    if (EVP_EncryptFinal_ex(ctx, ct.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed: " + sslError());
    }
    cipherLen += len;

    ct.resize(cipherLen);

    tagOut.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagOut.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed: " + sslError());
    }

    EVP_CIPHER_CTX_free(ctx);
    return ct;
}

// ============================================================
// Helper: AES-256-GCM decrypt + verify
// ============================================================

std::vector<unsigned char> osslCryptoPki::aesGcmDecrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& tag)
{
    if (key.size() != 32)
        throw std::runtime_error("AES-256-GCM key must be 32 bytes");
    if (iv.size() != 12)
        throw std::runtime_error("AES-256-GCM IV must be 12 bytes");
    if (tag.size() != 16)
        throw std::runtime_error("AES-GCM tag must be 16 bytes");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_CIPHER_CTX_new failed: " + sslError());

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed: " + sslError());
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed: " + sslError());
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex (key+iv) failed: " + sslError());
    }

    std::vector<unsigned char> pt(ciphertext.size() + 16);
    int len = 0;
    if (EVP_DecryptUpdate(ctx, pt.data(), &len, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed: " + sslError());
    }

    int plainLen = len;

    // Set the expected authentication tag BEFORE DecryptFinal
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<unsigned char*>(tag.data())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed: " + sslError());
    }

    int finalLen = 0;
    int rc = EVP_DecryptFinal_ex(ctx, pt.data() + len, &finalLen);
    EVP_CIPHER_CTX_free(ctx);

    if (rc != 1)
        throw std::runtime_error("AES-GCM authentication tag verification failed");

    plainLen += finalLen;
    pt.resize(plainLen);
    return pt;
}

// ============================================================
// RSA encryption with OAEP-SHA256
// ============================================================

std::vector<unsigned char> osslCryptoPki::rsaEncrypt(
    const osslCertificate&              cert,
    const std::vector<unsigned char>&   plaintext)
{
    EVP_PKEY* pkey = X509_get0_pubkey(cert.native());
    if (!pkey)
        throw std::runtime_error("rsaEncrypt: X509_get0_pubkey failed");

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
        throw std::runtime_error("rsaEncrypt: certificate does not contain an RSA key");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx)
        throw std::runtime_error("rsaEncrypt: EVP_PKEY_CTX_new failed: " + sslError());

    if (EVP_PKEY_encrypt_init(ctx) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("rsaEncrypt: EVP_PKEY_encrypt_init failed: " + sslError());
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("rsaEncrypt: EVP_PKEY_CTX_set_rsa_padding failed: " + sslError());
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("rsaEncrypt: EVP_PKEY_CTX_set_rsa_oaep_md failed: " + sslError());
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("rsaEncrypt: EVP_PKEY_CTX_set_rsa_mgf1_md failed: " + sslError());
    }

    size_t outLen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outLen, plaintext.data(), plaintext.size()) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("rsaEncrypt: EVP_PKEY_encrypt (size) failed: " + sslError());
    }

    std::vector<unsigned char> ciphertext(outLen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outLen, plaintext.data(),
                         plaintext.size()) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("rsaEncrypt: EVP_PKEY_encrypt (final) failed: " + sslError());
    }

    ciphertext.resize(outLen);
    EVP_PKEY_CTX_free(ctx);
    return ciphertext;
}

// ============================================================
// RSA decryption with OAEP-SHA256
// ============================================================

std::vector<unsigned char> osslCryptoPki::rsaDecrypt(
    const std::string&                  privKeyPem,
    const std::vector<unsigned char>&   ciphertext)
{
    EVP_PKEY* pkey = loadPrivateKey(privKeyPem);
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
    {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("rsaDecrypt: private key is not RSA");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_free(pkey);
    if (!ctx)
        throw std::runtime_error("rsaDecrypt: EVP_PKEY_CTX_new failed: " + sslError());

    if (EVP_PKEY_decrypt_init(ctx) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("rsaDecrypt: EVP_PKEY_decrypt_init failed: " + sslError());
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("rsaDecrypt: EVP_PKEY_CTX_set_rsa_padding failed: " + sslError());
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("rsaDecrypt: EVP_PKEY_CTX_set_rsa_oaep_md failed: " + sslError());
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("rsaDecrypt: EVP_PKEY_CTX_set_rsa_mgf1_md failed: " + sslError());
    }

    size_t outLen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, ciphertext.data(), ciphertext.size()) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("rsaDecrypt: EVP_PKEY_decrypt (size) failed: " + sslError());
    }

    std::vector<unsigned char> plaintext(outLen);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outLen, ciphertext.data(),
                         ciphertext.size()) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("rsaDecrypt: EVP_PKEY_decrypt (final) failed: " + sslError());
    }

    plaintext.resize(outLen);
    EVP_PKEY_CTX_free(ctx);
    return plaintext;
}

// ============================================================
// ECC encryption with ECIES
// ============================================================

std::vector<unsigned char> osslCryptoPki::eccEncrypt(
    const osslCertificate&              cert,
    const std::vector<unsigned char>&   plaintext)
{
    EVP_PKEY* recipPub = X509_get0_pubkey(cert.native());
    if (!recipPub)
        throw std::runtime_error("eccEncrypt: X509_get0_pubkey failed");

    if (EVP_PKEY_base_id(recipPub) != EVP_PKEY_EC)
        throw std::runtime_error("eccEncrypt: certificate does not contain an EC key");

    // Generate ephemeral key on the same curve
    EVP_PKEY_CTX* paramCtx = EVP_PKEY_CTX_new(recipPub, nullptr);
    if (!paramCtx)
        throw std::runtime_error("eccEncrypt: EVP_PKEY_CTX_new (ephemeral) failed: " + sslError());

    if (EVP_PKEY_keygen_init(paramCtx) != 1)
    {
        EVP_PKEY_CTX_free(paramCtx);
        throw std::runtime_error("eccEncrypt: EVP_PKEY_keygen_init failed: " + sslError());
    }

    EVP_PKEY* ephemeralKey = nullptr;
    if (EVP_PKEY_keygen(paramCtx, &ephemeralKey) != 1)
    {
        EVP_PKEY_CTX_free(paramCtx);
        throw std::runtime_error("eccEncrypt: EVP_PKEY_keygen failed: " + sslError());
    }
    EVP_PKEY_CTX_free(paramCtx);

    // Serialize ephemeral public key to DER
    int pubLen = i2d_PUBKEY(ephemeralKey, nullptr);
    if (pubLen < 0)
    {
        EVP_PKEY_free(ephemeralKey);
        throw std::runtime_error("eccEncrypt: i2d_PUBKEY (size) failed: " + sslError());
    }

    std::vector<unsigned char> ephPubDer(pubLen);
    unsigned char* p = ephPubDer.data();
    if (i2d_PUBKEY(ephemeralKey, &p) != pubLen)
    {
        EVP_PKEY_free(ephemeralKey);
        throw std::runtime_error("eccEncrypt: i2d_PUBKEY (final) failed: " + sslError());
    }

    if (pubLen > 65535)
    {
        EVP_PKEY_free(ephemeralKey);
        throw std::runtime_error("eccEncrypt: ephemeral public key too large");
    }

    // Generate random IV
    std::vector<unsigned char> iv(12);
    if (RAND_bytes(iv.data(), 12) != 1)
    {
        EVP_PKEY_free(ephemeralKey);
        throw std::runtime_error("eccEncrypt: RAND_bytes failed: " + sslError());
    }

    // Perform ECDH
    std::vector<unsigned char> sharedSecret = ecdhDeriveShared(ephemeralKey, recipPub);

    // Derive AES key via HKDF
    std::vector<unsigned char> salt = ephPubDer;
    salt.insert(salt.end(), iv.begin(), iv.end());
    std::vector<unsigned char> aesKey = hkdfSha256(sharedSecret, salt,
                                                    "osslCrypto ECIES AES-256-GCM", 32);

    // Encrypt plaintext
    std::vector<unsigned char> tag;
    std::vector<unsigned char> ct = aesGcmEncrypt(aesKey, iv, plaintext, tag);

    // Assemble ECIES blob
    std::vector<unsigned char> blob;
    // Magic
    blob.insert(blob.end(), kMagic, kMagic + 4);
    // Version
    blob.push_back(kVersion);
    // Flags
    blob.push_back(0x00);
    // Ephemeral pubkey length (big-endian uint16)
    uint16_t pubKeyLen = static_cast<uint16_t>(ephPubDer.size());
    blob.push_back(static_cast<unsigned char>((pubKeyLen >> 8) & 0xFF));
    blob.push_back(static_cast<unsigned char>(pubKeyLen & 0xFF));
    // Ephemeral pubkey
    blob.insert(blob.end(), ephPubDer.begin(), ephPubDer.end());
    // IV
    blob.insert(blob.end(), iv.begin(), iv.end());
    // Tag
    blob.insert(blob.end(), tag.begin(), tag.end());
    // Ciphertext length (big-endian uint32)
    uint32_t ctLen = static_cast<uint32_t>(ct.size());
    blob.push_back(static_cast<unsigned char>((ctLen >> 24) & 0xFF));
    blob.push_back(static_cast<unsigned char>((ctLen >> 16) & 0xFF));
    blob.push_back(static_cast<unsigned char>((ctLen >> 8) & 0xFF));
    blob.push_back(static_cast<unsigned char>(ctLen & 0xFF));
    // Ciphertext
    blob.insert(blob.end(), ct.begin(), ct.end());

    EVP_PKEY_free(ephemeralKey);
    return blob;
}

// ============================================================
// ECC decryption with ECIES
// ============================================================

std::vector<unsigned char> osslCryptoPki::eccDecrypt(
    const std::string&                  privKeyPem,
    const std::vector<unsigned char>&   ciphertext)
{
    // Validate minimum size (magic + version + flags + len fields = 8 bytes at least)
    if (ciphertext.size() < 8)
        throw std::runtime_error("eccDecrypt: ciphertext too small");

    // Validate magic
    if (ciphertext[0] != kMagic[0] || ciphertext[1] != kMagic[1] ||
        ciphertext[2] != kMagic[2] || ciphertext[3] != kMagic[3])
        throw std::runtime_error("eccDecrypt: invalid ECIES magic header");

    // Validate version
    if (ciphertext[4] != kVersion)
        throw std::runtime_error("eccDecrypt: unsupported ECIES version");

    // Parse ephemeral pubkey length
    uint16_t pubKeyLen = (static_cast<uint16_t>(ciphertext[6]) << 8) |
                         static_cast<uint16_t>(ciphertext[7]);

    // Validate total size
    size_t minSize = 8 + pubKeyLen + 12 + 16 + 4;  // headers + pubkey + iv + tag + ctLen
    if (ciphertext.size() < minSize)
        throw std::runtime_error("eccDecrypt: ciphertext structure size mismatch");

    // Extract ephemeral public key and deserialize
    const unsigned char* pubKeyPtr = ciphertext.data() + 8;
    EVP_PKEY* ephemeralPub = d2i_PUBKEY(nullptr, &pubKeyPtr, pubKeyLen);
    if (!ephemeralPub)
        throw std::runtime_error("eccDecrypt: d2i_PUBKEY failed: " + sslError());

    // Extract IV
    std::vector<unsigned char> iv(ciphertext.begin() + 8 + pubKeyLen,
                                  ciphertext.begin() + 8 + pubKeyLen + 12);

    // Extract tag
    std::vector<unsigned char> tag(ciphertext.begin() + 8 + pubKeyLen + 12,
                                   ciphertext.begin() + 8 + pubKeyLen + 12 + 16);

    // Parse ciphertext length
    const unsigned char* ctLenPtr = ciphertext.data() + 8 + pubKeyLen + 28;
    uint32_t ctLen = (static_cast<uint32_t>(ctLenPtr[0]) << 24) |
                     (static_cast<uint32_t>(ctLenPtr[1]) << 16) |
                     (static_cast<uint32_t>(ctLenPtr[2]) << 8) |
                     static_cast<uint32_t>(ctLenPtr[3]);

    // Validate total size with ciphertext
    size_t expectedSize = 8 + pubKeyLen + 12 + 16 + 4 + ctLen;
    if (ciphertext.size() != expectedSize)
    {
        EVP_PKEY_free(ephemeralPub);
        throw std::runtime_error("eccDecrypt: ciphertext size mismatch with header");
    }

    // Extract ciphertext
    std::vector<unsigned char> ct(ciphertext.begin() + 8 + pubKeyLen + 32,
                                  ciphertext.end());

    // Load private key
    EVP_PKEY* privKey = loadPrivateKey(privKeyPem);
    if (EVP_PKEY_base_id(privKey) != EVP_PKEY_EC)
    {
        EVP_PKEY_free(privKey);
        EVP_PKEY_free(ephemeralPub);
        throw std::runtime_error("eccDecrypt: private key is not EC");
    }

    // Perform ECDH
    std::vector<unsigned char> sharedSecret = ecdhDeriveShared(privKey, ephemeralPub);
    EVP_PKEY_free(privKey);
    EVP_PKEY_free(ephemeralPub);

    // Derive AES key via HKDF
    std::vector<unsigned char> ephPubDer(ciphertext.begin() + 8,
                                         ciphertext.begin() + 8 + pubKeyLen);
    std::vector<unsigned char> salt = ephPubDer;
    salt.insert(salt.end(), iv.begin(), iv.end());
    std::vector<unsigned char> aesKey = hkdfSha256(sharedSecret, salt,
                                                    "osslCrypto ECIES AES-256-GCM", 32);

    // Decrypt
    return aesGcmDecrypt(aesKey, iv, ct, tag);
}

// ============================================================
// Generic encrypt/decrypt with auto-detection
// ============================================================

std::vector<unsigned char> osslCryptoPki::pkiEncrypt(
    const osslCertificate&              cert,
    const std::vector<unsigned char>&   plaintext)
{
    EVP_PKEY* pkey = X509_get0_pubkey(cert.native());
    if (!pkey)
        throw std::runtime_error("pkiEncrypt: X509_get0_pubkey failed");

    int id = EVP_PKEY_base_id(pkey);
    if (id == EVP_PKEY_RSA)
        return rsaEncrypt(cert, plaintext);
    else if (id == EVP_PKEY_EC)
        return eccEncrypt(cert, plaintext);
    else
        throw std::runtime_error("pkiEncrypt: unsupported key type");
}

std::vector<unsigned char> osslCryptoPki::pkiDecrypt(
    const std::string&                  privKeyPem,
    const std::vector<unsigned char>&   ciphertext)
{
    EVP_PKEY* pkey = loadPrivateKey(privKeyPem);
    int id = EVP_PKEY_base_id(pkey);
    EVP_PKEY_free(pkey);

    if (id == EVP_PKEY_RSA)
        return rsaDecrypt(privKeyPem, ciphertext);
    else if (id == EVP_PKEY_EC)
        return eccDecrypt(privKeyPem, ciphertext);
    else
        throw std::runtime_error("pkiDecrypt: unsupported key type");
}

// ============================================================
// String convenience overloads
// ============================================================

std::vector<unsigned char> osslCryptoPki::pkiEncrypt(
    const osslCertificate&  cert,
    const std::string&      plaintext)
{
    std::vector<unsigned char> pt(plaintext.begin(), plaintext.end());
    return pkiEncrypt(cert, pt);
}

std::string osslCryptoPki::pkiDecryptToString(
    const std::string&                  privKeyPem,
    const std::vector<unsigned char>&   ciphertext)
{
    std::vector<unsigned char> pt = pkiDecrypt(privKeyPem, ciphertext);
    return std::string(pt.begin(), pt.end());
}
