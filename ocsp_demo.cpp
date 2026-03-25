#include "osslOcspClient.h"
#include <iostream>
#include <iomanip>
#include <ctime>

static std::string fmtTime(std::time_t t)
{
    if (!t) return "(none)";
    struct tm utc {};
#if defined(_WIN32)
    gmtime_s(&utc, &t);
#else
    gmtime_r(&t, &utc);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return buf;
}

static void printResult(const osslOcspClient::ValidationResult& r)
{
    std::cout << std::left;
    std::cout << "  " << std::setw(20) << "Status"
              << r.statusText << '\n';
    std::cout << "  " << std::setw(20) << "Responder URL"
              << r.responderURL << '\n';
    if (!r.responderName.empty())
        std::cout << "  " << std::setw(20) << "Responder Name"
                  << r.responderName << '\n';
    std::cout << "  " << std::setw(20) << "This Update"
              << fmtTime(r.thisUpdate) << '\n';
    std::cout << "  " << std::setw(20) << "Next Update"
              << fmtTime(r.nextUpdate) << '\n';
    if (r.status == osslOcspClient::Status::Revoked)
    {
        std::cout << "  " << std::setw(20) << "Revoked At"
                  << fmtTime(r.revokedAt) << '\n';
        std::cout << "  " << std::setw(20) << "Revoke Reason"
                  << r.revokeReasonText << '\n';
    }
    std::cout << "  " << std::setw(20) << "Nonce Verified"
              << (r.nonceVerified ? "yes" : "no") << '\n';
}

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        std::cerr
            << "Usage: " << argv[0]
            << " <leaf.pem> <issuer.pem> [ocsp-url-override]\n"
            << "\nExamples:\n"
            << "  " << argv[0] << " leaf.pem issuer.pem\n"
            << "  " << argv[0]
            << " leaf.pem issuer.pem http://ocsp.example.com\n";
        return 1;
    }

    try
    {
        osslCertificate leaf   = osslCertificate::fromFile(argv[1]);
        osslCertificate issuer = osslCertificate::fromFile(argv[2]);

        std::cout << "Leaf   : " << leaf.subjectDN()   << '\n';
        std::cout << "Issuer : " << issuer.subjectDN() << '\n';

        // OCSP URLs embedded in the leaf certificate
        auto urls = osslOcspClient::ocspURLs(leaf);
        if (urls.empty())
            std::cout << "AIA OCSP: (none in certificate)\n";
        else
            for (auto& u : urls)
                std::cout << "AIA OCSP: " << u << '\n';

        osslOcspClient client(issuer);
        client.setNonce(true);

        if (argc > 3)
        {
            std::cout << "Override URL: " << argv[3] << '\n';
            client.setResponderURL(argv[3]);
        }

        std::cout << "\nQuerying OCSP responder ...\n\n";
        auto result = client.validate(leaf);
        printResult(result);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "\nError: " << ex.what() << '\n';
        return 1;
    }

    return 0;
}
