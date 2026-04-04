#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# test-readme-commands.sh
#
# Exercises the sample commands from README.md against real JARs built by
# "mvn package". Every test writes its output to a temp directory that is
# cleaned up at the end.
#
# Prerequisites:
#   - Java 11+
#   - "mvn package" has been run (fat JARs exist under module target/ dirs)
#
# Usage:
#   cd demo && bash test-readme-commands.sh
# ---------------------------------------------------------------------------

set -euo pipefail

# ── Paths ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SIGNER_JAR="$PROJECT_ROOT/jsignpdf-pades/target/jsignpdf-pades-0.1.0-SNAPSHOT.jar"
VALIDATOR_JAR="$PROJECT_ROOT/validator/target/jsignpdf-pades-validator-0.1.0-SNAPSHOT.jar"

# Test assets bundled in this directory
KEYSTORE="$SCRIPT_DIR/keystore.p12"
DOCUMENT="$SCRIPT_DIR/document.pdf"
LOGO="$SCRIPT_DIR/logo.png"

# FreeTSA - free timestamp service with a well-known certificate (no auth needed)
TSA_URL="http://freetsa.org/tsr"

# PostSignum demo TSA  (https://www.postsignum.cz/testovaci_casova_razitka.html)
# Uses a certificate not in default cacerts - see "cannot-execute" section.
POSTSIGNUM_TSA_URL="https://demo.postsignum.cz:444/DEMO-TSS/HttpTspServer/"
POSTSIGNUM_TSA_USER="demoTSA"
POSTSIGNUM_TSA_PASS="demoTSA2010"

# ── Helpers ────────────────────────────────────────────────────────────────
WORK_DIR=""
PASS=0
FAIL=0
SKIP=0

setup() {
    WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/jsignpdf-readme-test.XXXXXX")
    echo "Working directory: $WORK_DIR"
    echo ""

    for jar in "$SIGNER_JAR" "$VALIDATOR_JAR"; do
        if [[ ! -f "$jar" ]]; then
            echo "ERROR: JAR not found: $jar"
            echo "Run 'mvn package' first."
            exit 1
        fi
    done

    for asset in "$KEYSTORE" "$DOCUMENT" "$LOGO"; do
        if [[ ! -f "$asset" ]]; then
            echo "ERROR: Test asset not found: $asset"
            exit 1
        fi
    done
}

cleanup() {
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
    fi
    echo ""
    echo "========================================"
    echo " Results: $PASS passed, $FAIL failed, $SKIP skipped"
    echo "========================================"
    if [[ $FAIL -gt 0 ]]; then
        exit 1
    fi
}

trap cleanup EXIT

# Run a test.  Usage: run_test "description" command [args...]
run_test() {
    local desc="$1"; shift
    echo -n "TEST: $desc ... "
    local out="$WORK_DIR/_output.log"
    if "$@" >"$out" 2>&1; then
        echo "OK"
        PASS=$((PASS + 1))
    else
        echo "FAIL (exit=$?)"
        echo "  ---- output ----"
        tail -5 "$out" | sed 's/^/  /'
        echo "  ----------------"
        FAIL=$((FAIL + 1))
    fi
}

# Copy a fresh unsigned document into the work dir under the given name.
fresh_doc() {
    local name="${1:-document.pdf}"
    cp "$DOCUMENT" "$WORK_DIR/$name"
    echo "$WORK_DIR/$name"
}

# ── Setup ──────────────────────────────────────────────────────────────────
setup

# ══════════════════════════════════════════════════════════════════════════
#  Other Commands
# ══════════════════════════════════════════════════════════════════════════

echo "=== Other Commands ==="

run_test "Print help (signer)" \
    java -jar "$SIGNER_JAR" -h

run_test "Print help (validator)" \
    java -jar "$VALIDATOR_JAR" -h

run_test "List available keystore types" \
    java -jar "$SIGNER_JAR" -lkt

run_test "List keys in a keystore" \
    java -jar "$SIGNER_JAR" -lk -kst PKCS12 -ksf "$KEYSTORE" -ksp password

echo ""

# ══════════════════════════════════════════════════════════════════════════
#  Signing
# ══════════════════════════════════════════════════════════════════════════

echo "=== Signing ==="

# README: Basic signing
DOC=$(fresh_doc "basic.pdf")
run_test "Basic signing" \
    java -jar "$SIGNER_JAR" -kst PKCS12 -ksf "$KEYSTORE" -ksp password -ka mykey "$DOC"

# README: Visible signature with text
DOC=$(fresh_doc "visible.pdf")
run_test "Visible signature with text" \
    java -jar "$SIGNER_JAR" -kst PKCS12 -ksf "$KEYSTORE" -ksp password \
        -V -pg 1 -llx 50 -lly 50 -urx 250 -ury 120 \
        -r "Approved" -l "Prague" "$DOC"

# README: Image-only visible signature
DOC=$(fresh_doc "image-only.pdf")
run_test "Image-only visible signature" \
    java -jar "$SIGNER_JAR" -kst PKCS12 -ksf "$KEYSTORE" -ksp password \
        -V --image-only --bg-path "$LOGO" -llx 50 -lly 50 -urx 200 -ury 100 "$DOC"

# README: Add blank page for signature
DOC=$(fresh_doc "blank-page.pdf")
run_test "Add blank page for signature" \
    java -jar "$SIGNER_JAR" -kst PKCS12 -ksf "$KEYSTORE" -ksp password \
        -V --add-blank-page -llx 100 -lly 300 -urx 400 -ury 500 "$DOC"

# README: Encrypt and sign
DOC=$(fresh_doc "encrypt.pdf")
run_test "Encrypt and sign" \
    java -jar "$SIGNER_JAR" -kst PKCS12 -ksf "$KEYSTORE" -ksp password \
        --encrypt-before-sign -opwd owner123 -upwd user123 "$DOC"

echo ""

# ══════════════════════════════════════════════════════════════════════════
#  Signing with PostSignum demo TSA (requires network)
# ══════════════════════════════════════════════════════════════════════════

echo "=== Signing with timestamp (FreeTSA - requires network) ==="

DOC=$(fresh_doc "timestamp.pdf")
run_test "Sign with timestamp (FreeTSA)" \
    java -jar "$SIGNER_JAR" -kst PKCS12 -ksf "$KEYSTORE" -ksp password \
        -ts "$TSA_URL" "$DOC"

echo ""

# ══════════════════════════════════════════════════════════════════════════
#  PostSignum demo TSA (requires network + openssl for cert extraction)
#  https://www.postsignum.cz/testovaci_casova_razitka.html
# ══════════════════════════════════════════════════════════════════════════

echo "=== PostSignum demo TSA (requires network) ==="

# Approach 1: Extract TLS root cert from the server, import into a truststore,
#             and pass it to the JVM via -Djavax.net.ssl.trustStore.
#
# The demo TSA at demo.postsignum.cz:444 uses a production TLS certificate
# signed by "PostSignum Root QCA 4" which is not in the default Java cacerts.
# We extract it from the TLS handshake and build a minimal truststore.
if command -v openssl >/dev/null 2>&1; then
    POSTSIGNUM_ROOT_PEM="$WORK_DIR/postsignum-root.pem"
    POSTSIGNUM_TRUSTSTORE="$WORK_DIR/postsignum-truststore.p12"

    echo Q | openssl s_client -connect demo.postsignum.cz:444 -showcerts 2>/dev/null | \
        awk '/-----BEGIN CERTIFICATE-----/{n++} n==3' > "$POSTSIGNUM_ROOT_PEM"

    keytool -importcert -noprompt -alias postsignum-root-qca4 \
        -file "$POSTSIGNUM_ROOT_PEM" \
        -keystore "$POSTSIGNUM_TRUSTSTORE" -storepass changeit -storetype PKCS12 \
        >/dev/null 2>&1

    DOC=$(fresh_doc "postsignum-trust.pdf")
    run_test "PostSignum TSA with imported root cert (-Djavax.net.ssl.trustStore)" \
        java -Djavax.net.ssl.trustStore="$POSTSIGNUM_TRUSTSTORE" \
             -Djavax.net.ssl.trustStorePassword=changeit \
             -Djavax.net.ssl.trustStoreType=PKCS12 \
            -jar "$SIGNER_JAR" -kst PKCS12 -ksf "$KEYSTORE" -ksp password -ka mykey \
            -ta PASSWORD -tsu "$POSTSIGNUM_TSA_USER" -tsp "$POSTSIGNUM_TSA_PASS" \
            -ts "$POSTSIGNUM_TSA_URL" "$DOC"
else
    echo "  (openssl not found - skipping PostSignum root cert approach)"
    SKIP=$((SKIP + 1))
fi

# Approach 2: Use --insecure-relax-tls to bypass TLS certificate verification.
# This sets a TrustStrategy on the DSS TimestampDataLoader that accepts any cert.
DOC=$(fresh_doc "postsignum-insecure.pdf")
run_test "PostSignum TSA with --insecure-relax-tls" \
    java -jar "$SIGNER_JAR" -kst PKCS12 -ksf "$KEYSTORE" -ksp password -ka mykey \
        --insecure-relax-tls \
        -ta PASSWORD -tsu "$POSTSIGNUM_TSA_USER" -tsp "$POSTSIGNUM_TSA_PASS" \
        -ts "$POSTSIGNUM_TSA_URL" "$DOC"

echo ""

# ══════════════════════════════════════════════════════════════════════════
#  Validation
# ══════════════════════════════════════════════════════════════════════════

echo "=== Validation ==="

# We need a signed file. Use the basic signing output.
SIGNED="$WORK_DIR/basic_signed.pdf"
if [[ ! -f "$SIGNED" ]]; then
    echo "  (no signed file from basic signing - skipping validation tests)"
    SKIP=$((SKIP + 5))
else
    # Note: The test keystore uses a self-signed certificate, so DSS validation
    # reports INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND. The validator exits
    # with code 1 ("invalid") which is correct behavior. We use run_test_expect
    # to accept exit code 1 as success for these tests.

    # Run a test that expects a specific non-zero exit code.
    # Usage: run_test_expect EXIT_CODE "description" command [args...]
    run_test_expect() {
        local expected_exit="$1"; shift
        local desc="$1"; shift
        echo -n "TEST: $desc ... "
        local out="$WORK_DIR/_output.log"
        local rc=0
        "$@" >"$out" 2>&1 || rc=$?
        if [[ $rc -eq $expected_exit ]]; then
            echo "OK (exit $rc as expected)"
            PASS=$((PASS + 1))
        elif [[ $rc -eq 0 ]]; then
            echo "UNEXPECTED OK (expected exit $expected_exit)"
            FAIL=$((FAIL + 1))
        else
            echo "FAIL (exit=$rc, expected $expected_exit)"
            echo "  ---- output ----"
            tail -5 "$out" | sed 's/^/  /'
            echo "  ----------------"
            FAIL=$((FAIL + 1))
        fi
    }

    # README: Validate with text output
    run_test_expect 1 "Validate with text output (self-signed -> INDETERMINATE)" \
        java -jar "$VALIDATOR_JAR" --skip-revocation "$SIGNED"

    # README: JSON output
    run_test_expect 1 "Validate with JSON output" \
        java -jar "$VALIDATOR_JAR" --skip-revocation -f JSON "$SIGNED"

    # README: ETSI report
    run_test_expect 1 "Validate with ETSI report" \
        java -jar "$VALIDATOR_JAR" --skip-revocation -f ETSI "$SIGNED"

    # README: Quiet mode (exit 0=valid, 1=invalid, 2=error; 0 or 1 are both acceptable)
    echo -n "TEST: Validate quiet mode (exit code) ... "
    quiet_rc=0
    java -jar "$VALIDATOR_JAR" --skip-revocation -q "$SIGNED" >/dev/null 2>&1 || quiet_rc=$?
    if [[ $quiet_rc -eq 0 || $quiet_rc -eq 1 ]]; then
        echo "OK (exit $quiet_rc)"
        PASS=$((PASS + 1))
    else
        echo "FAIL (exit $quiet_rc, expected 0 or 1)"
        FAIL=$((FAIL + 1))
    fi

    # README: Skip online revocation checks
    run_test_expect 1 "Validate with --skip-revocation" \
        java -jar "$VALIDATOR_JAR" --skip-revocation "$SIGNED"
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════
#  Cannot-execute samples (listed for reference)
# ══════════════════════════════════════════════════════════════════════════

echo "=== Samples that CANNOT be executed directly ==="
echo ""
echo "The following README examples require resources or conditions not"
echo "available in this self-contained test:"
echo ""
echo "  1. Validate with EU trusted list"
echo "     java -jar jsignpdf-pades-validator.jar --trust-use-default-lotl signed.pdf"
echo "     Reason: LOTL loading requires network access and takes several minutes"
echo "             to download and parse the full EU Trusted Lists."
echo ""
echo "  2. TSA with client-certificate authentication"
echo "     (the -ta CERTIFICATE / -tskt / -tskf / -tskp options)"
echo "     Reason: Requires a TSA server that enforces mutual TLS and a"
echo "             matching client certificate. No public demo server available."
echo ""
echo "  3. Signing with PKCS#11 / smart card / HSM"
echo "     (the --pkcs11-config-file option)"
echo "     Reason: Requires physical hardware or a software PKCS#11 token."
echo ""
