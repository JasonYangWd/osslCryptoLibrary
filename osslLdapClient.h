#pragma once

#include "osslCertificate.h"

#include <string>
#include <vector>
#include <functional>
#include <stdexcept>

// Forward-declare LDAP handle so callers don't need to include ldap.h
struct ldap;
typedef struct ldap LDAP;

/**
 * osslLdapClient
 *
 * Connects to an LDAP / LDAPS directory and retrieves X.509 certificates
 * stored in the standard attributes:
 *   - userCertificate;binary   (end-entity certs on user/computer objects)
 *   - cACertificate;binary     (CA certs on CA objects)
 *   - crossCertificatePair;binary (forward/reverse cross-certs)
 *
 * Typical usage:
 *
 *   osslLdapClient client("ldap://dc.corp.local", 389);
 *   client.bindSimple("cn=reader,dc=corp,dc=local", "password");
 *
 *   auto certs = client.searchByEmail("alice@corp.local",
 *                                      "dc=corp,dc=local");
 *   for (auto& c : certs)
 *       std::cout << c.subjectDN() << '\n';
 */
class osslLdapClient
{
public:
    // ----------------------------------------------------------------
    // Connection
    // ----------------------------------------------------------------

    /**
     * @param uri   Full LDAP URI, e.g. "ldap://192.168.1.1:389"
     *              or "ldaps://dc.corp.local:636"
     */
    explicit osslLdapClient(const std::string& uri);
    ~osslLdapClient();

    // Non-copyable
    osslLdapClient(const osslLdapClient&)            = delete;
    osslLdapClient& operator=(const osslLdapClient&) = delete;

    osslLdapClient(osslLdapClient&&) noexcept;
    osslLdapClient& operator=(osslLdapClient&&) noexcept;

    // ----------------------------------------------------------------
    // TLS / SSL options  (call before bind)
    // ----------------------------------------------------------------

    /**
     * Require a valid server certificate.  Default: LDAP_OPT_X_TLS_DEMAND.
     * Pass LDAP_OPT_X_TLS_NEVER to disable verification (test/dev only).
     */
    void setTLSVerify(int mode);          // LDAP_OPT_X_TLS_*

    /** Path to a PEM CA bundle to use for LDAPS certificate verification. */
    void setTLSCACertFile(const std::string& path);

    // ----------------------------------------------------------------
    // Authentication
    // ----------------------------------------------------------------

    /** Anonymous bind. */
    void bindAnonymous();

    /** Simple (cleartext) bind — use only over LDAPS or StartTLS. */
    void bindSimple(const std::string& bindDN, const std::string& password);

    // ----------------------------------------------------------------
    // Certificate retrieval
    // ----------------------------------------------------------------

    /**
     * Generic search: returns all certificates found in
     * userCertificate;binary, cACertificate;binary, and
     * crossCertificatePair;binary within the scope subtree of baseDN.
     *
     * @param baseDN  Search base, e.g. "dc=corp,dc=local"
     * @param filter  RFC 4515 LDAP filter, e.g. "(mail=alice@corp.local)"
     */
    std::vector<osslCertificate> search(const std::string& baseDN,
                                        const std::string& filter) const;

    /** Find certs for the object at an exact distinguished name. */
    std::vector<osslCertificate> searchByDN(const std::string& dn) const;

    /** Search by mail / rfc822 email address. */
    std::vector<osslCertificate> searchByEmail(const std::string& email,
                                               const std::string& baseDN) const;

    /** Search by Common Name (cn attribute). */
    std::vector<osslCertificate> searchByCommonName(const std::string& cn,
                                                    const std::string& baseDN) const;

    /** Search by raw uid attribute. */
    std::vector<osslCertificate> searchByUID(const std::string& uid,
                                             const std::string& baseDN) const;

    /**
     * Retrieve CA certificates from objects of class certificationAuthority.
     * Useful for building a local trust store from an AD/LDAP PKI.
     */
    std::vector<osslCertificate> fetchCACertificates(const std::string& baseDN) const;

    // ----------------------------------------------------------------
    // Connection state
    // ----------------------------------------------------------------

    bool isConnected() const { return m_ldap != nullptr; }

    /** Explicit disconnect (also called by destructor). */
    void disconnect();

private:
    LDAP*       m_ldap = nullptr;
    std::string m_uri;

    // Internal helper: extract DER certs from a single ldap message entry
    void extractCertsFromEntry(void* entry,
                               std::vector<osslCertificate>& out) const;

    static std::string ldapError(int rc);
};
