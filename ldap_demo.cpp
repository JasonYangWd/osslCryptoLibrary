#include "osslLdapClient.h"
#include <iostream>
#include <iomanip>

static void printCert(const osslCertificate& c, int idx)
{
    std::cout << "  [" << idx << "] "
              << std::left << std::setw(40) << c.subjectDN()
              << "  " << c.publicKeyAlgorithm()
              << " " << c.publicKeyBits() << "-bit"
              << "  sig=" << c.signatureAlgorithm()
              << "  expires=" << c.notAfterStr()
              << (c.isExpired() ? " [EXPIRED]" : "")
              << '\n';
}

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        std::cerr
            << "Usage: " << argv[0]
            << " <ldap-uri> <base-dn> [bind-dn] [password] [email-filter]\n"
            << '\n'
            << "Examples:\n"
            << "  " << argv[0]
            << " ldap://192.168.1.1 dc=corp,dc=local\n"
            << "  " << argv[0]
            << " ldap://192.168.1.1 dc=corp,dc=local"
               " cn=reader,dc=corp,dc=local secret alice@corp.local\n"
            << "  " << argv[0]
            << " ldaps://dc.corp.local:636 dc=corp,dc=local"
               " cn=reader,dc=corp,dc=local secret\n";
        return 1;
    }

    const std::string uri    = argv[1];
    const std::string baseDN = argv[2];
    const std::string bindDN = (argc > 3) ? argv[3] : "";
    const std::string passwd = (argc > 4) ? argv[4] : "";
    const std::string email  = (argc > 5) ? argv[5] : "";

    try
    {
        std::cout << "Connecting to " << uri << " ...\n";
        osslLdapClient client(uri);

        // For LDAPS / StartTLS in dev/test you may want to relax cert check:
        // client.setTLSVerify(LDAP_OPT_X_TLS_NEVER);

        if (!bindDN.empty())
        {
            std::cout << "Binding as " << bindDN << " ...\n";
            client.bindSimple(bindDN, passwd);
        }
        else
        {
            std::cout << "Anonymous bind ...\n";
            client.bindAnonymous();
        }

        // --- Search by email ---
        if (!email.empty())
        {
            std::cout << "\nSearching for certs with email: " << email << '\n';
            auto certs = client.searchByEmail(email, baseDN);
            std::cout << "  Found " << certs.size() << " certificate(s)\n";
            int i = 0;
            for (auto& c : certs) printCert(c, i++);
        }

        // --- Fetch all user certs ---
        {
            std::cout << "\nFetching all userCertificate objects under " << baseDN << " ...\n";
            auto certs = client.search(baseDN, "(userCertificate=*)");
            std::cout << "  Found " << certs.size() << " certificate(s)\n";
            int i = 0;
            for (auto& c : certs) printCert(c, i++);
        }

        // --- Fetch CA certs ---
        {
            std::cout << "\nFetching CA certificates under " << baseDN << " ...\n";
            auto certs = client.fetchCACertificates(baseDN);
            std::cout << "  Found " << certs.size() << " CA certificate(s)\n";
            int i = 0;
            for (auto& c : certs) printCert(c, i++);
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Error: " << ex.what() << '\n';
        return 1;
    }

    return 0;
}
