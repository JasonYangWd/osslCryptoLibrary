#include "osslCertificate.h"

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

static void printSeparator(char c = '-', int width = 60)
{
    std::cout << std::string(width, c) << '\n';
}

static void printList(const std::string& label, const std::vector<std::string>& items)
{
    std::cout << "  " << std::left << std::setw(18) << label;
    if (items.empty())
    {
        std::cout << "(none)\n";
        return;
    }
    std::cout << items[0] << '\n';
    for (size_t i = 1; i < items.size(); ++i)
        std::cout << "  " << std::string(18, ' ') << items[i] << '\n';
}

static void showCert(const std::string& path)
{
    printSeparator('=');
    std::cout << "  " << fs::path(path).filename().string() << '\n';
    printSeparator('=');

    osslCertificate cert = osslCertificate::fromFile(path);

    // --- Identity ---
    std::cout << "  " << std::left << std::setw(18) << "Common Name"  << cert.commonName()          << '\n';
    std::cout << "  " << std::setw(18) << "Organization"              << cert.organization()        << '\n';
    std::cout << "  " << std::setw(18) << "Email"                     << cert.email()               << '\n';
    std::cout << "  " << std::setw(18) << "Country"                   << cert.country()             << '\n';
    printSeparator();

    // --- Issuer ---
    std::cout << "  " << std::setw(18) << "Issuer DN"                 << cert.issuerDN()            << '\n';
    printSeparator();

    // --- Validity ---
    std::cout << "  " << std::setw(18) << "Version"  << "v" << (cert.version() + 1)                << '\n';
    std::cout << "  " << std::setw(18) << "Serial"                    << cert.serialNumber()        << '\n';
    std::cout << "  " << std::setw(18) << "Not Before"                << cert.notBeforeStr()        << '\n';
    std::cout << "  " << std::setw(18) << "Not After"                 << cert.notAfterStr()         << '\n';
    std::cout << "  " << std::setw(18) << "Expired"   << (cert.isExpired() ? "YES" : "no")         << '\n';
    std::cout << "  " << std::setw(18) << "Is CA"     << (cert.isCA()      ? "yes" : "no")         << '\n';
    printSeparator();

    // --- Public Key ---
    std::cout << "  " << std::setw(18) << "Key Algorithm"             << cert.publicKeyAlgorithm()  << '\n';
    std::cout << "  " << std::setw(18) << "Key Bits"                  << cert.publicKeyBits()       << '\n';
    printSeparator();

    // --- Signature ---
    std::cout << "  " << std::setw(18) << "Sig Algorithm"             << cert.signatureAlgorithm()  << '\n';

    // Print signature truncated for readability
    std::string sigHex = cert.signatureHex();
    if (sigHex.size() > 59)
        sigHex = sigHex.substr(0, 56) + "...";
    std::cout << "  " << std::setw(18) << "Signature"                 << sigHex                     << '\n';
    printSeparator();

    // --- Fingerprints ---
    std::cout << "  " << std::setw(18) << "SHA-1  FP"                 << cert.fingerprintSHA1()     << '\n';
    std::cout << "  " << std::setw(18) << "SHA-256 FP"                << cert.fingerprintSHA256()   << '\n';
    printSeparator();

    // --- Extensions ---
    std::cout << "  " << std::setw(18) << "SKID"                      << cert.subjectKeyIdentifier()   << '\n';
    std::cout << "  " << std::setw(18) << "AKID"                      << cert.authorityKeyIdentifier() << '\n';
    printList("SANs",         cert.subjectAltNames());
    printList("Key Usage",    cert.keyUsage());
    printList("Ext Key Usage",cert.extendedKeyUsage());

    std::cout << '\n';
}

int main(int argc, char* argv[])
{
    // Collect paths: from args or scan test_certs/
    std::vector<std::string> paths;

    if (argc > 1)
    {
        for (int i = 1; i < argc; ++i)
            paths.push_back(argv[i]);
    }
    else
    {
        fs::path dir = "test_certs";
        if (!fs::exists(dir))
        {
            std::cerr << "No arguments given and ./test_certs/ not found.\n"
                      << "Usage: " << argv[0] << " [cert.pem ...]\n";
            return 1;
        }
        for (auto& entry : fs::directory_iterator(dir))
        {
            auto ext = entry.path().extension().string();
            if (ext == ".pem" || ext == ".der" || ext == ".crt" || ext == ".cer")
                paths.push_back(entry.path().string());
        }
        std::sort(paths.begin(), paths.end());
    }

    std::cout << "\n  Loading " << paths.size() << " certificate(s)\n\n";

    int ok = 0, fail = 0;
    for (auto& p : paths)
    {
        try
        {
            showCert(p);
            ++ok;
        }
        catch (const std::exception& ex)
        {
            printSeparator('!');
            std::cerr << "  ERROR: " << p << "\n  " << ex.what() << '\n';
            printSeparator('!');
            ++fail;
        }
    }

    printSeparator('=');
    std::cout << "  Loaded " << ok << " OK, " << fail << " failed\n";
    printSeparator('=');
    return fail ? 1 : 0;
}
