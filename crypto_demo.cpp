#include "osslCertificate.h"
#include "osslCryptoPki.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

// ============================================================
// Helpers
// ============================================================

static std::string readFile(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("Cannot open file: " + path);

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

static void printHex(const std::string& label,
                     const std::vector<unsigned char>& data,
                     size_t maxBytes = 32)
{
    std::cout << label << " (" << data.size() << " bytes): ";
    size_t limit = std::min(maxBytes, data.size());
    for (size_t i = 0; i < limit; ++i)
    {
        std::cout << std::hex << std::uppercase << std::setfill('0')
                  << std::setw(2) << static_cast<int>(data[i]);
        if (i < limit - 1)
            std::cout << " ";
    }
    if (limit < data.size())
        std::cout << " ...";
    std::cout << std::dec << '\n';
}

// ============================================================
// Main
// ============================================================

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 3)
        {
            std::cerr << "Usage: crypto_demo <cert.pem> <privkey.pem>\n";
            std::cerr << "Example: crypto_demo test_certs/rsa2048_sha256.pem test_certs/rsa2048_sha256.key\n";
            return 1;
        }

        // Load certificate and private key
        osslCertificate cert = osslCertificate::fromFile(argv[1]);
        std::string privKeyPem = readFile(argv[2]);

        std::string algo = cert.publicKeyAlgorithm();
        int bits = cert.publicKeyBits();
        std::cout << "=== Certificate Info ===\n";
        std::cout << "CN            : " << cert.commonName() << '\n';
        std::cout << "Key algorithm : " << algo << '\n';
        std::cout << "Key bits      : " << bits << '\n';
        std::cout << '\n';

        // Test message
        const std::string plaintext = "Hello from osslCryptoPki! This is a test message for PKI encryption.";
        std::vector<unsigned char> ptBytes(plaintext.begin(), plaintext.end());

        // --- Generic pkiEncrypt / pkiDecrypt round-trip ---
        std::cout << "=== Generic pkiEncrypt / pkiDecrypt ===\n";
        std::cout << "Plaintext     : " << plaintext << '\n';

        auto ciphertext = osslCryptoPki::pkiEncrypt(cert, ptBytes);
        printHex("Ciphertext", ciphertext, 32);

        auto recovered = osslCryptoPki::pkiDecrypt(privKeyPem, ciphertext);
        std::string recoveredStr(recovered.begin(), recovered.end());
        std::cout << "Decrypted     : " << recoveredStr << '\n';
        bool match = (recoveredStr == plaintext);
        std::cout << "Match         : " << (match ? "YES ✓" : "NO ✗") << '\n';
        if (!match)
            throw std::runtime_error("Generic decrypt mismatch!");
        std::cout << '\n';

        // --- String convenience overload ---
        std::cout << "=== String Convenience Overload ===\n";
        auto ct2 = osslCryptoPki::pkiEncrypt(cert, plaintext);
        std::string pt2 = osslCryptoPki::pkiDecryptToString(privKeyPem, ct2);
        std::cout << "Decrypted     : " << pt2 << '\n';
        match = (pt2 == plaintext);
        std::cout << "Match         : " << (match ? "YES ✓" : "NO ✗") << '\n';
        if (!match)
            throw std::runtime_error("String overload decrypt mismatch!");
        std::cout << '\n';

        // --- Algorithm-specific tests ---
        if (algo == "rsaEncryption")
        {
            std::cout << "=== RSA-Specific Path ===\n";
            auto rsaCt = osslCryptoPki::rsaEncrypt(cert, ptBytes);
            printHex("RSA ciphertext", rsaCt, 32);

            auto rsaPt = osslCryptoPki::rsaDecrypt(privKeyPem, rsaCt);
            std::string rsaDecrypted(rsaPt.begin(), rsaPt.end());
            std::cout << "RSA decrypted : " << rsaDecrypted << '\n';
            match = (rsaDecrypted == plaintext);
            std::cout << "Match         : " << (match ? "YES ✓" : "NO ✗") << '\n';
            if (!match)
                throw std::runtime_error("RSA decrypt mismatch!");
            std::cout << '\n';
        }
        else if (algo == "id-ecPublicKey")
        {
            std::cout << "=== ECC-Specific Path (ECIES) ===\n";
            auto eccCt = osslCryptoPki::eccEncrypt(cert, ptBytes);
            printHex("ECIES blob", eccCt, 16);
            std::cout << "ECIES total sz: " << eccCt.size() << " bytes\n";

            auto eccPt = osslCryptoPki::eccDecrypt(privKeyPem, eccCt);
            std::string eccDecrypted(eccPt.begin(), eccPt.end());
            std::cout << "ECC decrypted : " << eccDecrypted << '\n';
            match = (eccDecrypted == plaintext);
            std::cout << "Match         : " << (match ? "YES ✓" : "NO ✗") << '\n';
            if (!match)
                throw std::runtime_error("ECC decrypt mismatch!");
            std::cout << '\n';
        }
        else
        {
            throw std::runtime_error("Unsupported key algorithm: " + algo);
        }

        std::cout << "=== All Tests Passed ===\n";
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "ERROR: " << ex.what() << '\n';
        return 1;
    }
}
