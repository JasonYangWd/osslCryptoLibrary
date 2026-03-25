#include "osslCertificate.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <sstream>
#include <iomanip>
#include <fstream>
#include <cstring>

// ============================================================
// Internal helpers
// ============================================================

std::string osslCertificate::sslError()
{
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

std::string osslCertificate::toHex(const unsigned char* buf, size_t len)
{
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
    {
        if (i > 0) oss << ':';
        oss << std::setw(2) << static_cast<unsigned>(buf[i]);
    }
    return oss.str();
}

std::string osslCertificate::nameField(X509_NAME* name, int nid) const
{
    if (!name) return {};
    int idx = X509_NAME_get_index_by_NID(name, nid, -1);
    if (idx < 0) return {};
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
    if (!entry) return {};
    ASN1_STRING* asn1 = X509_NAME_ENTRY_get_data(entry);
    if (!asn1) return {};
    unsigned char* utf8 = nullptr;
    int len = ASN1_STRING_to_UTF8(&utf8, asn1);
    if (len < 0 || !utf8) return {};
    std::string result(reinterpret_cast<char*>(utf8), static_cast<size_t>(len));
    OPENSSL_free(utf8);
    return result;
}

std::time_t osslCertificate::asn1TimeToTimeT(const ASN1_TIME* t)
{
    struct tm tm_s {};
    ASN1_TIME_to_tm(t, &tm_s);
#if defined(_WIN32)
    return _mkgmtime(&tm_s);
#else
    return timegm(&tm_s);
#endif
}

std::string osslCertificate::timeTToISO(std::time_t t)
{
    struct tm utc {};
#if defined(_WIN32)
    gmtime_s(&utc, &t);
#else
    gmtime_r(&t, &utc);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return std::string(buf);
}

std::string osslCertificate::fingerprint(const EVP_MD* md) const
{
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int  len = 0;
    if (X509_digest(m_cert, md, buf, &len) != 1)
        throw std::runtime_error("X509_digest failed: " + sslError());
    return toHex(buf, len);
}

// ============================================================
// Factory methods
// ============================================================

osslCertificate osslCertificate::fromFile(const std::string& path)
{
    // Try PEM first, then DER
    FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp)
        throw std::runtime_error("Cannot open file: " + path);

    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    if (!cert)
    {
        // Rewind and try DER
        std::rewind(fp);
        cert = d2i_X509_fp(fp, nullptr);
    }
    std::fclose(fp);

    if (!cert)
        throw std::runtime_error("Failed to parse certificate from file '" + path + "': " + sslError());

    return osslCertificate(cert);   // takes ownership
}

osslCertificate osslCertificate::fromPEM(const std::string& pem)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio)
        throw std::runtime_error("BIO_new_mem_buf failed");

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert)
        throw std::runtime_error("Failed to parse PEM certificate: " + sslError());

    return osslCertificate(cert);
}

osslCertificate osslCertificate::fromDER(const unsigned char* data, int len)
{
    X509* cert = d2i_X509(nullptr, &data, len);
    if (!cert)
        throw std::runtime_error("Failed to parse DER certificate: " + sslError());
    return osslCertificate(cert);
}

// ============================================================
// Construction / destruction
// ============================================================

osslCertificate::osslCertificate(X509* cert)
    : m_cert(cert)
{
    if (!m_cert)
        throw std::runtime_error("Null X509 pointer passed to osslCertificate");
}

osslCertificate::osslCertificate(const osslCertificate& other)
    : m_cert(other.m_cert)
{
    if (m_cert) X509_up_ref(m_cert);
}

osslCertificate& osslCertificate::operator=(const osslCertificate& other)
{
    if (this != &other)
    {
        X509_free(m_cert);
        m_cert = other.m_cert;
        if (m_cert) X509_up_ref(m_cert);
    }
    return *this;
}

osslCertificate::osslCertificate(osslCertificate&& other) noexcept
    : m_cert(other.m_cert)
{
    other.m_cert = nullptr;
}

osslCertificate& osslCertificate::operator=(osslCertificate&& other) noexcept
{
    if (this != &other)
    {
        X509_free(m_cert);
        m_cert = other.m_cert;
        other.m_cert = nullptr;
    }
    return *this;
}

osslCertificate::~osslCertificate()
{
    X509_free(m_cert);
}

// ============================================================
// Subject / Issuer
// ============================================================

static std::string dnToString(X509_NAME* name)
{
    if (!name) return {};
    BIO* bio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
    char* data = nullptr;
    long  len  = BIO_get_mem_data(bio, &data);
    std::string result(data, static_cast<size_t>(len));
    BIO_free(bio);
    return result;
}

std::string osslCertificate::subjectDN() const { return dnToString(X509_get_subject_name(m_cert)); }
std::string osslCertificate::issuerDN()  const { return dnToString(X509_get_issuer_name(m_cert));  }

std::string osslCertificate::commonName()          const { return nameField(X509_get_subject_name(m_cert), NID_commonName);             }
std::string osslCertificate::organization()        const { return nameField(X509_get_subject_name(m_cert), NID_organizationName);       }
std::string osslCertificate::organizationalUnit()  const { return nameField(X509_get_subject_name(m_cert), NID_organizationalUnitName); }
std::string osslCertificate::country()             const { return nameField(X509_get_subject_name(m_cert), NID_countryName);            }
std::string osslCertificate::stateOrProvince()     const { return nameField(X509_get_subject_name(m_cert), NID_stateOrProvinceName);    }
std::string osslCertificate::locality()            const { return nameField(X509_get_subject_name(m_cert), NID_localityName);           }

std::string osslCertificate::email() const
{
    // 1. Try subject emailAddress field
    std::string result = nameField(X509_get_subject_name(m_cert), NID_pkcs9_emailAddress);
    if (!result.empty()) return result;

    // 2. Try Subject Alternative Names (rfc822Name)
    GENERAL_NAMES* sans = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(m_cert, NID_subject_alt_name, nullptr, nullptr));
    if (!sans) return {};

    for (int i = 0; i < sk_GENERAL_NAME_num(sans); ++i)
    {
        GENERAL_NAME* gn = sk_GENERAL_NAME_value(sans, i);
        if (gn->type == GEN_EMAIL)
        {
            result = std::string(
                reinterpret_cast<const char*>(ASN1_STRING_get0_data(gn->d.rfc822Name)),
                static_cast<size_t>(ASN1_STRING_length(gn->d.rfc822Name)));
            break;
        }
    }
    GENERAL_NAMES_free(sans);
    return result;
}

// ============================================================
// Validity
// ============================================================

std::time_t osslCertificate::notBefore() const { return asn1TimeToTimeT(X509_get0_notBefore(m_cert)); }
std::time_t osslCertificate::notAfter()  const { return asn1TimeToTimeT(X509_get0_notAfter(m_cert));  }

std::string osslCertificate::notBeforeStr() const { return timeTToISO(notBefore()); }
std::string osslCertificate::notAfterStr()  const { return timeTToISO(notAfter());  }

bool osslCertificate::isExpired() const { return std::time(nullptr) > notAfter(); }

// ============================================================
// Serial / version
// ============================================================

std::string osslCertificate::serialNumber() const
{
    const ASN1_INTEGER* serial = X509_get0_serialNumber(m_cert);
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    char*   hex = BN_bn2hex(bn);
    std::string result(hex);
    OPENSSL_free(hex);
    BN_free(bn);
    return result;
}

int osslCertificate::version() const
{
    return static_cast<int>(X509_get_version(m_cert));
}

// ============================================================
// Public key
// ============================================================

std::string osslCertificate::publicKeyAlgorithm() const
{
    EVP_PKEY* pkey = X509_get0_pubkey(m_cert);
    if (!pkey) return {};
    int id = EVP_PKEY_base_id(pkey);
    return std::string(OBJ_nid2ln(id));
}

int osslCertificate::publicKeyBits() const
{
    EVP_PKEY* pkey = X509_get0_pubkey(m_cert);
    if (!pkey) return 0;
    return EVP_PKEY_bits(pkey);
}

std::string osslCertificate::publicKeyPEM() const
{
    EVP_PKEY* pkey = X509_get0_pubkey(m_cert);
    if (!pkey) return {};
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    char* data = nullptr;
    long  len  = BIO_get_mem_data(bio, &data);
    std::string result(data, static_cast<size_t>(len));
    BIO_free(bio);
    return result;
}

// ============================================================
// Signature
// ============================================================

std::string osslCertificate::signatureAlgorithm() const
{
    const X509_ALGOR* alg = nullptr;
    X509_get0_signature(nullptr, &alg, m_cert);
    if (!alg) return {};
    int nid = OBJ_obj2nid(alg->algorithm);
    return std::string(OBJ_nid2ln(nid));
}

std::vector<unsigned char> osslCertificate::signatureBytes() const
{
    const ASN1_BIT_STRING* sig = nullptr;
    X509_get0_signature(&sig, nullptr, m_cert);
    if (!sig) return {};
    const unsigned char* data = ASN1_STRING_get0_data(sig);
    int                  len  = ASN1_STRING_length(sig);
    return std::vector<unsigned char>(data, data + len);
}

std::string osslCertificate::signatureHex() const
{
    auto bytes = signatureBytes();
    return toHex(bytes.data(), bytes.size());
}

// ============================================================
// Extensions
// ============================================================

std::vector<std::string> osslCertificate::subjectAltNames() const
{
    std::vector<std::string> result;

    GENERAL_NAMES* sans = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(m_cert, NID_subject_alt_name, nullptr, nullptr));
    if (!sans) return result;

    for (int i = 0; i < sk_GENERAL_NAME_num(sans); ++i)
    {
        GENERAL_NAME* gn = sk_GENERAL_NAME_value(sans, i);
        std::string entry;

        switch (gn->type)
        {
            case GEN_DNS:
                entry = "DNS:" + std::string(
                    reinterpret_cast<const char*>(ASN1_STRING_get0_data(gn->d.dNSName)),
                    static_cast<size_t>(ASN1_STRING_length(gn->d.dNSName)));
                break;
            case GEN_EMAIL:
                entry = "email:" + std::string(
                    reinterpret_cast<const char*>(ASN1_STRING_get0_data(gn->d.rfc822Name)),
                    static_cast<size_t>(ASN1_STRING_length(gn->d.rfc822Name)));
                break;
            case GEN_URI:
                entry = "URI:" + std::string(
                    reinterpret_cast<const char*>(ASN1_STRING_get0_data(gn->d.uniformResourceIdentifier)),
                    static_cast<size_t>(ASN1_STRING_length(gn->d.uniformResourceIdentifier)));
                break;
            case GEN_IPADD:
            {
                // IPv4 (4 bytes) or IPv6 (16 bytes)
                const unsigned char* ip = ASN1_STRING_get0_data(gn->d.iPAddress);
                int iplen = ASN1_STRING_length(gn->d.iPAddress);
                std::ostringstream oss;
                oss << "IP:";
                if (iplen == 4)
                {
                    oss << static_cast<int>(ip[0]) << '.'
                        << static_cast<int>(ip[1]) << '.'
                        << static_cast<int>(ip[2]) << '.'
                        << static_cast<int>(ip[3]);
                }
                else
                {
                    oss << std::hex << std::uppercase << std::setfill('0');
                    for (int b = 0; b < iplen; b += 2)
                    {
                        if (b) oss << ':';
                        oss << std::setw(2) << static_cast<int>(ip[b])
                            << std::setw(2) << static_cast<int>(ip[b+1]);
                    }
                }
                entry = oss.str();
                break;
            }
            default:
                break;
        }

        if (!entry.empty())
            result.push_back(std::move(entry));
    }

    GENERAL_NAMES_free(sans);
    return result;
}

std::vector<std::string> osslCertificate::keyUsage() const
{
    std::vector<std::string> result;
    uint32_t usage = X509_get_key_usage(m_cert);
    if (usage == UINT32_MAX) return result;  // extension absent

    static const struct { uint32_t flag; const char* name; } bits[] = {
        { KU_DIGITAL_SIGNATURE,  "Digital Signature"  },
        { KU_NON_REPUDIATION,    "Non Repudiation"    },
        { KU_KEY_ENCIPHERMENT,   "Key Encipherment"   },
        { KU_DATA_ENCIPHERMENT,  "Data Encipherment"  },
        { KU_KEY_AGREEMENT,      "Key Agreement"      },
        { KU_KEY_CERT_SIGN,      "Certificate Sign"   },
        { KU_CRL_SIGN,           "CRL Sign"           },
        { KU_ENCIPHER_ONLY,      "Encipher Only"      },
        { KU_DECIPHER_ONLY,      "Decipher Only"      },
    };

    for (auto& b : bits)
        if (usage & b.flag)
            result.push_back(b.name);

    return result;
}

std::vector<std::string> osslCertificate::extendedKeyUsage() const
{
    std::vector<std::string> result;
    EXTENDED_KEY_USAGE* eku = static_cast<EXTENDED_KEY_USAGE*>(
        X509_get_ext_d2i(m_cert, NID_ext_key_usage, nullptr, nullptr));
    if (!eku) return result;

    for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i)
    {
        ASN1_OBJECT* obj = sk_ASN1_OBJECT_value(eku, i);
        char buf[128];
        OBJ_obj2txt(buf, sizeof(buf), obj, 0);  // 0 = use long name
        result.push_back(buf);
    }
    EXTENDED_KEY_USAGE_free(eku);
    return result;
}

std::string osslCertificate::subjectKeyIdentifier() const
{
    ASN1_OCTET_STRING* skid = static_cast<ASN1_OCTET_STRING*>(
        X509_get_ext_d2i(m_cert, NID_subject_key_identifier, nullptr, nullptr));
    if (!skid) return {};
    std::string result = toHex(ASN1_STRING_get0_data(skid),
                               static_cast<size_t>(ASN1_STRING_length(skid)));
    ASN1_OCTET_STRING_free(skid);
    return result;
}

std::string osslCertificate::authorityKeyIdentifier() const
{
    AUTHORITY_KEYID* akid = static_cast<AUTHORITY_KEYID*>(
        X509_get_ext_d2i(m_cert, NID_authority_key_identifier, nullptr, nullptr));
    if (!akid) return {};
    std::string result;
    if (akid->keyid)
        result = toHex(ASN1_STRING_get0_data(akid->keyid),
                       static_cast<size_t>(ASN1_STRING_length(akid->keyid)));
    AUTHORITY_KEYID_free(akid);
    return result;
}

bool osslCertificate::isCA() const
{
    return X509_check_ca(m_cert) > 0;
}

// ============================================================
// Fingerprints
// ============================================================

std::string osslCertificate::fingerprintSHA1()   const { return fingerprint(EVP_sha1());   }
std::string osslCertificate::fingerprintSHA256() const { return fingerprint(EVP_sha256()); }

// ============================================================
// Export
// ============================================================

std::string osslCertificate::toPEM() const
{
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, m_cert);
    char* data = nullptr;
    long  len  = BIO_get_mem_data(bio, &data);
    std::string result(data, static_cast<size_t>(len));
    BIO_free(bio);
    return result;
}

std::vector<unsigned char> osslCertificate::toDER() const
{
    unsigned char* buf = nullptr;
    int len = i2d_X509(m_cert, &buf);
    if (len < 0)
        throw std::runtime_error("i2d_X509 failed: " + sslError());
    std::vector<unsigned char> result(buf, buf + len);
    OPENSSL_free(buf);
    return result;
}
