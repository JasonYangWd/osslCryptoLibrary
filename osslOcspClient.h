#pragma once

#include "osslCertificate.h"

#include <string>
#include <vector>
#include <ctime>
#include <stdexcept>

/**
 * osslOcspClient
 *
 * Validates X.509 certificates against an OCSP responder using
 * OpenSSL's OCSP API over plain HTTP.
 *
 * The issuer certificate is required to build the OCSP CertID and to
 * verify the responder's signature on the response.
 *
 * Typical usage:
 *
 *   osslCertificate leaf   = osslCertificate::fromFile("leaf.pem");
 *   osslCertificate issuer = osslCertificate::fromFile("issuer.pem");
 *
 *   osslOcspClient ocsp(issuer);
 *   auto result = ocsp.validate(leaf);           // URL from AIA extension
 *
 *   if (result.status == osslOcspClient::Status::Good)
 *       std::cout << "Certificate is valid\n";
 */
class osslOcspClient
{
public:
    // ----------------------------------------------------------------
    // Status
    // ----------------------------------------------------------------

    enum class Status
    {
        Good,       // OCSP_CERTSTATUS_GOOD    — not revoked
        Revoked,    // OCSP_CERTSTATUS_REVOKED — revoked
        Unknown,    // OCSP_CERTSTATUS_UNKNOWN — responder doesn't know
    };

    /** Reason codes as defined in RFC 5280 §5.3.1 */
    enum class RevokeReason
    {
        Unspecified          = 0,
        KeyCompromise        = 1,
        CACompromise         = 2,
        AffiliationChanged   = 3,
        Superseded           = 4,
        CessationOfOperation = 5,
        CertificateHold      = 6,
        RemoveFromCRL        = 8,
        PrivilegeWithdrawn   = 9,
        AACompromise         = 10,
        None                 = -1,   // not revoked / not provided
    };

    struct ValidationResult
    {
        Status       status        = Status::Unknown;
        std::string  statusText;           // "good" / "revoked" / "unknown"

        // Timestamps from the OCSP response
        std::time_t  thisUpdate    = 0;    // time this response was produced
        std::time_t  nextUpdate    = 0;    // time next update is expected
        std::time_t  revokedAt     = 0;    // only set when status == Revoked

        RevokeReason revokeReason  = RevokeReason::None;
        std::string  revokeReasonText;

        // Responder info
        std::string  responderURL;         // URL actually queried
        std::string  responderName;        // from response (if by-name)

        // Nonce verified?
        bool nonceVerified = false;
    };

    // ----------------------------------------------------------------
    // Construction
    // ----------------------------------------------------------------

    /**
     * @param issuer  The certificate that signed the leaf being validated.
     *                Required to build the CertID and verify the response.
     */
    explicit osslOcspClient(const osslCertificate& issuer);
    ~osslOcspClient() = default;

    // ----------------------------------------------------------------
    // Options (set before calling validate)
    // ----------------------------------------------------------------

    /** Add a random nonce to the request (replay protection). Default: true. */
    void setNonce(bool enabled) { m_nonce = enabled; }

    /** Network + response timeout in seconds. Default: 10. */
    void setTimeout(int seconds) { m_timeoutSec = seconds; }

    /**
     * Override the OCSP URL instead of reading it from the AIA extension.
     * Useful for testing or internal responders.
     */
    void setResponderURL(const std::string& url) { m_overrideURL = url; }

    /**
     * Skip signature verification on the OCSP response.
     * Only for debugging — never use in production.
     */
    void setSkipVerify(bool skip) { m_skipVerify = skip; }

    // ----------------------------------------------------------------
    // Validation
    // ----------------------------------------------------------------

    /**
     * Validate @p cert against the OCSP responder.
     * The responder URL is taken from the certificate's AIA extension
     * unless overridden with setResponderURL().
     *
     * Throws std::runtime_error on network or protocol errors.
     */
    ValidationResult validate(const osslCertificate& cert) const;

    /**
     * Convenience: validate and throw if not Good.
     * Returns the result on success so callers can inspect timestamps.
     */
    ValidationResult validateOrThrow(const osslCertificate& cert) const;

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    /** Extract OCSP responder URLs from a certificate's AIA extension. */
    static std::vector<std::string> ocspURLs(const osslCertificate& cert);

    /** Human-readable status string. */
    static std::string statusText(Status s);

    /** Human-readable revocation reason string. */
    static std::string reasonText(RevokeReason r);

private:
    const osslCertificate& m_issuer;
    bool        m_nonce      = true;
    int         m_timeoutSec = 10;
    bool        m_skipVerify = false;
    std::string m_overrideURL;

    // Send an OCSP_REQUEST to @p url and return the raw DER response bytes.
    std::vector<unsigned char> sendRequest(const std::string& url,
                                           void* req) const;   // OCSP_REQUEST*

    // Parse URL into host, port, path
    struct ParsedURL
    {
        std::string host;
        std::string port;
        std::string path;
        bool        tls;
    };
    static ParsedURL parseURL(const std::string& url);

    static std::string sslError();
};
