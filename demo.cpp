#include "osslCertificate.h"
#include <iostream>
#include <iomanip>

static void printList(const std::string& label, const std::vector<std::string>& items)
{
    std::cout << label << ":\n";
    if (items.empty())
        std::cout << "  (none)\n";
    else
        for (auto& s : items)
            std::cout << "  " << s << '\n';
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <certificate.pem|.der>\n";
        return 1;
    }

    try
    {
        osslCertificate cert = osslCertificate::fromFile(argv[1]);

        std::cout << "=== osslCertificate demo ===\n\n";

        // Identity
        std::cout << "Subject DN    : " << cert.subjectDN()    << '\n';
        std::cout << "Issuer DN     : " << cert.issuerDN()     << '\n';
        std::cout << '\n';

        // Subject fields
        std::cout << "Common Name   : " << cert.commonName()          << '\n';
        std::cout << "Organization  : " << cert.organization()        << '\n';
        std::cout << "Org Unit      : " << cert.organizationalUnit()  << '\n';
        std::cout << "Country       : " << cert.country()             << '\n';
        std::cout << "State         : " << cert.stateOrProvince()     << '\n';
        std::cout << "Locality      : " << cert.locality()            << '\n';
        std::cout << "Email         : " << cert.email()               << '\n';
        std::cout << '\n';

        // Validity
        std::cout << "Version       : v" << (cert.version() + 1)      << '\n';
        std::cout << "Serial        : " << cert.serialNumber()         << '\n';
        std::cout << "Not Before    : " << cert.notBeforeStr()         << '\n';
        std::cout << "Not After     : " << cert.notAfterStr()          << '\n';
        std::cout << "Expired       : " << (cert.isExpired() ? "yes" : "no") << '\n';
        std::cout << "Is CA         : " << (cert.isCA()      ? "yes" : "no") << '\n';
        std::cout << '\n';

        // Public key
        std::cout << "PubKey Algo   : " << cert.publicKeyAlgorithm() << '\n';
        std::cout << "PubKey Bits   : " << cert.publicKeyBits()      << '\n';
        std::cout << '\n';

        // Signature
        std::cout << "Sig Algorithm : " << cert.signatureAlgorithm() << '\n';
        std::cout << "Signature     : " << cert.signatureHex()       << '\n';
        std::cout << '\n';

        // Fingerprints
        std::cout << "SHA-1  FP     : " << cert.fingerprintSHA1()   << '\n';
        std::cout << "SHA-256 FP    : " << cert.fingerprintSHA256() << '\n';
        std::cout << '\n';

        // Extensions
        std::cout << "SKID          : " << cert.subjectKeyIdentifier()   << '\n';
        std::cout << "AKID          : " << cert.authorityKeyIdentifier() << '\n';
        std::cout << '\n';

        printList("Subject Alt Names", cert.subjectAltNames());
        printList("Key Usage",         cert.keyUsage());
        printList("Ext Key Usage",     cert.extendedKeyUsage());
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Error: " << ex.what() << '\n';
        return 1;
    }

    return 0;
}
