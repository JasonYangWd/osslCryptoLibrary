#include "osslLdapClient.h"

// OpenLDAP C API
#define LDAP_DEPRECATED 0
#include <ldap.h>
#include <lber.h>

#include <cstring>
#include <sstream>

// ============================================================
// Attributes we look for in every entry
// ============================================================
static const char* CERT_ATTRS[] = {
    "userCertificate;binary",
    "cACertificate;binary",
    "crossCertificatePair;binary",
    nullptr
};

// ============================================================
// Helpers
// ============================================================

std::string osslLdapClient::ldapError(int rc)
{
    return std::string(ldap_err2string(rc));
}

static void checkRC(int rc, const char* op)
{
    if (rc != LDAP_SUCCESS)
        throw std::runtime_error(std::string(op) + " failed: " +
                                 ldap_err2string(rc));
}

// ============================================================
// Construction / destruction
// ============================================================

osslLdapClient::osslLdapClient(const std::string& uri)
    : m_uri(uri)
{
    int rc = ldap_initialize(&m_ldap, uri.c_str());
    checkRC(rc, "ldap_initialize");

    // Set LDAP v3
    int ver = LDAP_VERSION3;
    ldap_set_option(m_ldap, LDAP_OPT_PROTOCOL_VERSION, &ver);

    // Sensible timeout defaults (5 s)
    struct timeval tv { 5, 0 };
    ldap_set_option(m_ldap, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    ldap_set_option(m_ldap, LDAP_OPT_TIMEOUT,         &tv);
}

osslLdapClient::osslLdapClient(osslLdapClient&& other) noexcept
    : m_ldap(other.m_ldap), m_uri(std::move(other.m_uri))
{
    other.m_ldap = nullptr;
}

osslLdapClient& osslLdapClient::operator=(osslLdapClient&& other) noexcept
{
    if (this != &other)
    {
        disconnect();
        m_ldap = other.m_ldap;
        m_uri  = std::move(other.m_uri);
        other.m_ldap = nullptr;
    }
    return *this;
}

osslLdapClient::~osslLdapClient()
{
    disconnect();
}

void osslLdapClient::disconnect()
{
    if (m_ldap)
    {
        ldap_unbind_ext_s(m_ldap, nullptr, nullptr);
        m_ldap = nullptr;
    }
}

// ============================================================
// TLS options
// ============================================================

void osslLdapClient::setTLSVerify(int mode)
{
    // Global option — must be set before the TLS handshake
    ldap_set_option(nullptr, LDAP_OPT_X_TLS_REQUIRE_CERT, &mode);
}

void osslLdapClient::setTLSCACertFile(const std::string& path)
{
    ldap_set_option(nullptr, LDAP_OPT_X_TLS_CACERTFILE, path.c_str());
}

// ============================================================
// Authentication
// ============================================================

void osslLdapClient::bindAnonymous()
{
    struct berval cred { 0, nullptr };
    int rc = ldap_sasl_bind_s(m_ldap, nullptr, LDAP_SASL_SIMPLE,
                               &cred, nullptr, nullptr, nullptr);
    checkRC(rc, "ldap_sasl_bind_s (anonymous)");
}

void osslLdapClient::bindSimple(const std::string& bindDN,
                                const std::string& password)
{
    struct berval cred;
    cred.bv_val = const_cast<char*>(password.c_str());
    cred.bv_len = static_cast<ber_len_t>(password.size());

    int rc = ldap_sasl_bind_s(m_ldap, bindDN.c_str(), LDAP_SASL_SIMPLE,
                               &cred, nullptr, nullptr, nullptr);
    checkRC(rc, "ldap_sasl_bind_s (simple)");
}

// ============================================================
// Certificate extraction from one LDAP entry
// ============================================================

void osslLdapClient::extractCertsFromEntry(void* rawEntry,
                                           std::vector<osslCertificate>& out) const
{
    LDAPMessage* entry = static_cast<LDAPMessage*>(rawEntry);

    for (int i = 0; CERT_ATTRS[i] != nullptr; ++i)
    {
        struct berval** vals =
            ldap_get_values_len(m_ldap, entry, CERT_ATTRS[i]);

        if (!vals) continue;

        for (int j = 0; vals[j] != nullptr; ++j)
        {
            const auto* der =
                reinterpret_cast<const unsigned char*>(vals[j]->bv_val);
            int derlen = static_cast<int>(vals[j]->bv_len);

            // crossCertificatePair contains a SEQUENCE of two certs;
            // try to decode both halves gracefully.
            const unsigned char* p = der;
            while (p < der + derlen)
            {
                try
                {
                    osslCertificate cert =
                        osslCertificate::fromDER(p, static_cast<int>(der + derlen - p));
                    // Advance past the DER object just decoded
                    // (re-decode to find its length)
                    const unsigned char* tmp = p;
                    X509* x = d2i_X509(nullptr, &tmp, static_cast<int>(der + derlen - p));
                    if (x)
                    {
                        p = tmp;   // tmp was advanced by d2i_X509
                        X509_free(x);
                    }
                    else break;

                    out.push_back(std::move(cert));
                }
                catch (...) { break; }
            }
        }

        ldap_value_free_len(vals);
    }
}

// ============================================================
// Generic search
// ============================================================

std::vector<osslCertificate>
osslLdapClient::search(const std::string& baseDN,
                       const std::string& filter) const
{
    std::vector<osslCertificate> result;

    // Non-const cast: libldap API takes char* even for in-params
    char* attrs[] = {
        const_cast<char*>("userCertificate;binary"),
        const_cast<char*>("cACertificate;binary"),
        const_cast<char*>("crossCertificatePair;binary"),
        nullptr
    };

    LDAPMessage* msg = nullptr;
    struct timeval tv { 10, 0 };

    int rc = ldap_search_ext_s(
        m_ldap,
        baseDN.c_str(),
        LDAP_SCOPE_SUBTREE,
        filter.c_str(),
        attrs,
        0,           // attrsonly = false
        nullptr, nullptr, &tv,
        LDAP_NO_LIMIT,
        &msg);

    if (rc != LDAP_SUCCESS)
    {
        if (msg) ldap_msgfree(msg);
        throw std::runtime_error("ldap_search_ext_s failed: " + ldapError(rc));
    }

    for (LDAPMessage* entry = ldap_first_entry(m_ldap, msg);
         entry != nullptr;
         entry = ldap_next_entry(m_ldap, entry))
    {
        extractCertsFromEntry(entry, result);
    }

    ldap_msgfree(msg);
    return result;
}

// ============================================================
// Convenience search wrappers
// ============================================================

std::vector<osslCertificate>
osslLdapClient::searchByDN(const std::string& dn) const
{
    std::vector<osslCertificate> result;

    char* attrs[] = {
        const_cast<char*>("userCertificate;binary"),
        const_cast<char*>("cACertificate;binary"),
        const_cast<char*>("crossCertificatePair;binary"),
        nullptr
    };

    LDAPMessage* msg = nullptr;
    struct timeval tv { 10, 0 };

    int rc = ldap_search_ext_s(
        m_ldap,
        dn.c_str(),
        LDAP_SCOPE_BASE,     // exact DN — base scope
        "(objectClass=*)",
        attrs, 0,
        nullptr, nullptr, &tv,
        LDAP_NO_LIMIT,
        &msg);

    if (rc != LDAP_SUCCESS)
    {
        if (msg) ldap_msgfree(msg);
        throw std::runtime_error("searchByDN failed: " + ldapError(rc));
    }

    for (LDAPMessage* entry = ldap_first_entry(m_ldap, msg);
         entry;
         entry = ldap_next_entry(m_ldap, entry))
    {
        extractCertsFromEntry(entry, result);
    }

    ldap_msgfree(msg);
    return result;
}

std::vector<osslCertificate>
osslLdapClient::searchByEmail(const std::string& email,
                              const std::string& baseDN) const
{
    // RFC 4524: mail attribute; also check userPrincipalName for AD
    std::string filter =
        "(|(mail=" + email + ")(userPrincipalName=" + email + "))";
    return search(baseDN, filter);
}

std::vector<osslCertificate>
osslLdapClient::searchByCommonName(const std::string& cn,
                                   const std::string& baseDN) const
{
    return search(baseDN, "(cn=" + cn + ")");
}

std::vector<osslCertificate>
osslLdapClient::searchByUID(const std::string& uid,
                            const std::string& baseDN) const
{
    return search(baseDN, "(uid=" + uid + ")");
}

std::vector<osslCertificate>
osslLdapClient::fetchCACertificates(const std::string& baseDN) const
{
    // certificationAuthority objects hold cACertificate;binary
    return search(baseDN,
        "(|(objectClass=certificationAuthority)"
         "(objectClass=pkiCA)"
         "(objectClass=cRLDistributionPoint))");
}
