#pragma once

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <string>
#include <vector>
#include <stdexcept>
#include <ctime>

/**
 * osslCertificate
 *
 * Wraps an OpenSSL X509 certificate and exposes its properties
 * through a clean C++ interface. Supports loading from PEM/DER
 * files or raw PEM strings.
 */
class osslCertificate
{
public:
    // ----------------------------------------------------------------
    // Construction / destruction
    // ----------------------------------------------------------------

    /** Load from a PEM or DER file on disk. */
    static osslCertificate fromFile(const std::string& path);

    /** Load from a PEM-encoded string in memory. */
    static osslCertificate fromPEM(const std::string& pem);

    /** Load from a DER-encoded buffer in memory. */
    static osslCertificate fromDER(const unsigned char* data, int len);

    /** Take ownership of an existing OpenSSL X509 pointer (ref-counted). */
    explicit osslCertificate(X509* cert);

    osslCertificate(const osslCertificate& other);
    osslCertificate& operator=(const osslCertificate& other);

    osslCertificate(osslCertificate&& other) noexcept;
    osslCertificate& operator=(osslCertificate&& other) noexcept;

    ~osslCertificate();

    // ----------------------------------------------------------------
    // Subject / Issuer fields
    // ----------------------------------------------------------------

    /** Full distinguished name, e.g. "C=US, O=Example, CN=test.example.com" */
    std::string subjectDN() const;
    std::string issuerDN()  const;

    /** Individual subject fields (returns "" if not present). */
    std::string commonName()     const;   // CN
    std::string organization()   const;   // O
    std::string organizationalUnit() const; // OU
    std::string country()        const;   // C
    std::string stateOrProvince() const;  // ST
    std::string locality()       const;   // L

    /**
     * Email address from the subject (emailAddress / E field).
     * Also checks Subject Alternative Names of type rfc822Name.
     */
    std::string email() const;

    // ----------------------------------------------------------------
    // Validity
    // ----------------------------------------------------------------

    std::time_t notBefore() const;
    std::time_t notAfter()  const;

    /** Human-readable ISO-8601 timestamps. */
    std::string notBeforeStr() const;
    std::string notAfterStr()  const;

    bool isExpired() const;

    // ----------------------------------------------------------------
    // Serial / version
    // ----------------------------------------------------------------

    /** Hex-encoded serial number. */
    std::string serialNumber() const;

    /** Certificate version (0 = v1, 2 = v3). */
    int version() const;

    // ----------------------------------------------------------------
    // Public key
    // ----------------------------------------------------------------

    /** Key algorithm name, e.g. "rsaEncryption", "id-ecPublicKey". */
    std::string publicKeyAlgorithm() const;

    /** Key size in bits (RSA/DSA) or curve size for EC. */
    int publicKeyBits() const;

    /** PEM-encoded public key. */
    std::string publicKeyPEM() const;

    // ----------------------------------------------------------------
    // Signature
    // ----------------------------------------------------------------

    /** Signature algorithm name, e.g. "sha256WithRSAEncryption". */
    std::string signatureAlgorithm() const;

    /** Raw signature bytes. */
    std::vector<unsigned char> signatureBytes() const;

    /** Hex-encoded signature. */
    std::string signatureHex() const;

    // ----------------------------------------------------------------
    // Extensions
    // ----------------------------------------------------------------

    /** Subject Alternative Names (DNS, IP, email, URI). */
    std::vector<std::string> subjectAltNames() const;

    /** Key Usage string list, e.g. {"Digital Signature", "Key Encipherment"}. */
    std::vector<std::string> keyUsage() const;

    /** Extended Key Usage OID text list, e.g. {"TLS Web Server Authentication"}. */
    std::vector<std::string> extendedKeyUsage() const;

    /** Subject Key Identifier (hex). */
    std::string subjectKeyIdentifier() const;

    /** Authority Key Identifier (hex). */
    std::string authorityKeyIdentifier() const;

    /** Whether the certificate is a CA certificate. */
    bool isCA() const;

    // ----------------------------------------------------------------
    // Fingerprints
    // ----------------------------------------------------------------

    std::string fingerprintSHA1()   const;
    std::string fingerprintSHA256() const;

    // ----------------------------------------------------------------
    // Export
    // ----------------------------------------------------------------

    std::string toPEM() const;
    std::vector<unsigned char> toDER() const;

    // ----------------------------------------------------------------
    // Raw access
    // ----------------------------------------------------------------

    /** Returns the underlying OpenSSL X509 pointer (not transferred). */
    X509* native() const { return m_cert; }

private:
    X509* m_cert = nullptr;

    // Helper: extract a named field from a X509_NAME
    std::string nameField(X509_NAME* name, int nid) const;

    // Helper: ASN1_TIME -> std::time_t
    static std::time_t asn1TimeToTimeT(const ASN1_TIME* t);

    // Helper: format a std::time_t as ISO-8601 UTC
    static std::string timeTToISO(std::time_t t);

    // Helper: compute a digest fingerprint
    std::string fingerprint(const EVP_MD* md) const;

    // Helper: hex-encode a byte buffer
    static std::string toHex(const unsigned char* buf, size_t len);

    // Helper: last OpenSSL error as string
    static std::string sslError();
};
