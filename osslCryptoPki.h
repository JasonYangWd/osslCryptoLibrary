#pragma once

#include "osslCertificate.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

#include <string>
#include <vector>
#include <stdexcept>

/**
 * osslCryptoPki
 *
 * All-static class providing PKI encryption and decryption using OpenSSL.
 * Supports RSA (RSA-OAEP-SHA256) and ECC (ECIES: ephemeral ECDH +
 * HKDF-SHA256 + AES-256-GCM).
 *
 * Never instantiated. All methods are static.
 *
 * RSA usage:
 *   auto ct = osslCryptoPki::rsaEncrypt(cert, plaintext);
 *   auto pt = osslCryptoPki::rsaDecrypt(privKeyPem, ct);
 *
 * ECC usage:
 *   auto ct = osslCryptoPki::eccEncrypt(cert, plaintext);
 *   auto pt = osslCryptoPki::eccDecrypt(privKeyPem, ct);
 *
 * Generic usage (auto-detects from private key type):
 *   auto ct = osslCryptoPki::pkiEncrypt(cert, plaintext);
 *   auto pt = osslCryptoPki::pkiDecrypt(privKeyPem, ct);
 *
 * ECIES ciphertext binary layout:
 *   [4]  magic      "OCRY" (0x4F 0x43 0x52 0x59)
 *   [1]  version    0x01
 *   [1]  flags      0x00 (reserved)
 *   [2]  pubkey_len big-endian uint16
 *   [N]  ephemeral  DER SubjectPublicKeyInfo (uncompressed EC point)
 *   [12] iv         AES-GCM nonce (random)
 *   [16] tag        AES-GCM authentication tag
 *   [4]  ct_len     big-endian uint32
 *   [M]  ciphertext AES-256-GCM encrypted payload
 */
class osslCryptoPki
{
public:
    // ----------------------------------------------------------------
    // RSA — RSA-OAEP-SHA256
    // ----------------------------------------------------------------

    /**
     * Encrypt @p plaintext with the RSA public key from @p cert.
     * Uses OAEP padding with SHA-256 as both the hash and MGF1 hash.
     * @p cert must contain an RSA public key; throws otherwise.
     * Ciphertext is raw bytes (size == RSA modulus size in bytes).
     */
    static std::vector<unsigned char> rsaEncrypt(
        const osslCertificate&              cert,
        const std::vector<unsigned char>&   plaintext);

    /**
     * Decrypt @p ciphertext with the RSA private key in PEM string @p privKeyPem.
     * Uses OAEP-SHA256 padding, matching rsaEncrypt.
     * Throws if padding verification fails or key is wrong type.
     */
    static std::vector<unsigned char> rsaDecrypt(
        const std::string&                  privKeyPem,
        const std::vector<unsigned char>&   ciphertext);

    // ----------------------------------------------------------------
    // ECC — ECIES (ephemeral ECDH + HKDF-SHA256 + AES-256-GCM)
    // ----------------------------------------------------------------

    /**
     * Encrypt @p plaintext with the EC public key from @p cert.
     * Generates an ephemeral EC key on the same curve, computes ECDH,
     * derives AES-256 key via HKDF-SHA256, and encrypts with AES-256-GCM.
     * @p cert must contain an EC public key; throws otherwise.
     * Returns a self-describing ECIES blob (see class doc for layout).
     */
    static std::vector<unsigned char> eccEncrypt(
        const osslCertificate&              cert,
        const std::vector<unsigned char>&   plaintext);

    /**
     * Decrypt an ECIES blob produced by eccEncrypt.
     * @p privKeyPem must be a PEM-encoded EC private key.
     * Throws if the magic header is missing, authentication tag fails,
     * or the key is wrong type/curve.
     */
    static std::vector<unsigned char> eccDecrypt(
        const std::string&                  privKeyPem,
        const std::vector<unsigned char>&   ciphertext);

    // ----------------------------------------------------------------
    // Generic — auto-detects key type from private key PEM
    // ----------------------------------------------------------------

    /**
     * Encrypt @p plaintext using the key type in @p cert.
     * Dispatches to rsaEncrypt or eccEncrypt; throws if neither.
     */
    static std::vector<unsigned char> pkiEncrypt(
        const osslCertificate&              cert,
        const std::vector<unsigned char>&   plaintext);

    /**
     * Decrypt @p ciphertext using @p privKeyPem.
     * Loads the key, detects RSA vs EC via EVP_PKEY_base_id(),
     * and dispatches to rsaDecrypt or eccDecrypt.
     */
    static std::vector<unsigned char> pkiDecrypt(
        const std::string&                  privKeyPem,
        const std::vector<unsigned char>&   ciphertext);

    // ----------------------------------------------------------------
    // String convenience overloads
    // ----------------------------------------------------------------

    /** Encrypt a UTF-8 string. Returns binary ciphertext. */
    static std::vector<unsigned char> pkiEncrypt(
        const osslCertificate&  cert,
        const std::string&      plaintext);

    /** Decrypt to a UTF-8 string. */
    static std::string pkiDecryptToString(
        const std::string&                  privKeyPem,
        const std::vector<unsigned char>&   ciphertext);

    // ----------------------------------------------------------------
    // Deleted: not instantiable
    // ----------------------------------------------------------------

    osslCryptoPki()                              = delete;
    osslCryptoPki(const osslCryptoPki&)          = delete;
    osslCryptoPki& operator=(const osslCryptoPki&) = delete;

private:
    // ---- Internal helpers -------------------------------------------

    /** Last OpenSSL error as a string (same pattern as osslCertificate). */
    static std::string sslError();

    /**
     * Load a private key from a PEM string.
     * Returns an owning EVP_PKEY*; caller must EVP_PKEY_free.
     */
    static EVP_PKEY* loadPrivateKey(const std::string& pem);

    /**
     * Derive a 32-byte AES-256 key from @p sharedSecret using HKDF-SHA256.
     * @p salt    = concat(ephemeralPubKeyDER, iv12bytes)
     * @p info    = "osslCrypto ECIES AES-256-GCM"
     */
    static std::vector<unsigned char> hkdfSha256(
        const std::vector<unsigned char>& sharedSecret,
        const std::vector<unsigned char>& salt,
        const std::string&                info,
        size_t                            outputLen);

    /**
     * Perform ECDH between @p ourKey (private) and @p peerKey (public).
     * Returns the raw shared secret bytes.
     */
    static std::vector<unsigned char> ecdhDeriveShared(
        EVP_PKEY* ourKey,
        EVP_PKEY* peerKey);

    /**
     * AES-256-GCM encrypt. Returns ciphertext; writes tag to @p tagOut (16 bytes).
     */
    static std::vector<unsigned char> aesGcmEncrypt(
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv,
        const std::vector<unsigned char>& plaintext,
        std::vector<unsigned char>&       tagOut);

    /**
     * AES-256-GCM decrypt + verify tag. Throws if authentication fails.
     */
    static std::vector<unsigned char> aesGcmDecrypt(
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv,
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& tag);

    // ECIES blob field offsets (for documentation clarity)
    static constexpr size_t kMagicOffset      = 0;
    static constexpr size_t kVersionOffset    = 4;
    static constexpr size_t kFlagsOffset      = 5;
    static constexpr size_t kPubKeyLenOffset  = 6;
    static constexpr size_t kPubKeyOffset     = 8;
    static constexpr size_t kMagicSize        = 4;
    static constexpr unsigned char kMagic[4]  = {0x4F, 0x43, 0x52, 0x59};
    static constexpr unsigned char kVersion   = 0x01;
    static constexpr size_t kIvSize           = 12;
    static constexpr size_t kTagSize          = 16;
    static constexpr size_t kAesKeySize       = 32;
    static constexpr size_t kCtLenSize        = 4;
};
