#!/usr/bin/env bash
# gen_test_certs.sh
# Generates RSA (2048/3072/4096) and ECC (P-256/P-384/P-521) test certificates
# with varying signature hash algorithms, then runs the demo against each.

set -euo pipefail

DEMO="./build/demo"
OUT="./test_certs"
mkdir -p "$OUT"

PASS=0
FAIL=0

run_demo() {
    local label="$1"
    local pemfile="$2"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $label"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if "$DEMO" "$pemfile" 2>&1; then
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] demo returned non-zero"
        FAIL=$((FAIL + 1))
    fi
}

gen_rsa() {
    local bits="$1"
    local hash="$2"
    local label="RSA-${bits} / ${hash}"
    local base="${OUT}/rsa${bits}_${hash}"

    openssl req -x509 \
        -newkey "rsa:${bits}" \
        -keyout "${base}.key" \
        -out    "${base}.pem" \
        -days 365 -nodes \
        -"${hash}" \
        -subj "/C=DE/ST=Bavaria/L=Munich/O=RSA Test/OU=CryptoLab/CN=rsa${bits}.test.local/emailAddress=rsa${bits}@test.local" \
        -addext "subjectAltName=DNS:rsa${bits}.test.local,email:rsa${bits}@test.local" \
        -addext "keyUsage=digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" \
        2>/dev/null

    run_demo "$label" "${base}.pem"
}

gen_ec() {
    local curve="$1"
    local hash="$2"
    local label="ECC ${curve} / ${hash}"
    local base="${OUT}/ec_${curve}_${hash}"

    openssl req -x509 \
        -newkey "ec" \
        -pkeyopt "ec_paramgen_curve:${curve}" \
        -keyout "${base}.key" \
        -out    "${base}.pem" \
        -days 365 -nodes \
        -"${hash}" \
        -subj "/C=US/ST=California/L=Palo Alto/O=ECC Test/OU=CryptoLab/CN=${curve}.test.local/emailAddress=${curve}@test.local" \
        -addext "subjectAltName=DNS:${curve}.test.local,DNS:www.${curve}.test.local,email:${curve}@test.local,IP:192.168.1.1" \
        -addext "keyUsage=digitalSignature" \
        -addext "extendedKeyUsage=serverAuth,clientAuth" \
        2>/dev/null

    run_demo "$label" "${base}.pem"
}

# --- RSA variants ---
gen_rsa 2048 sha256
gen_rsa 2048 sha384
gen_rsa 2048 sha512
gen_rsa 3072 sha256
gen_rsa 3072 sha384
gen_rsa 4096 sha256
gen_rsa 4096 sha512

# --- ECC variants ---
gen_ec prime256v1 sha256
gen_ec prime256v1 sha384
gen_ec secp384r1  sha256
gen_ec secp384r1  sha384
gen_ec secp384r1  sha512
gen_ec secp521r1  sha256
gen_ec secp521r1  sha512

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Generated certs are in: ${OUT}/"
ls "$OUT"/*.pem 2>/dev/null | sed 's|^|  |'
