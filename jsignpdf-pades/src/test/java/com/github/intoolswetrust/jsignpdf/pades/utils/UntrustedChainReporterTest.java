package com.github.intoolswetrust.jsignpdf.pades.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.TestConstants;

/**
 * Tests that a DSS untrusted-chain failure is turned into something a user can act on. DSS names the offending
 * certificates only by a token id ({@code C-<SHA-256 hex>}), which cannot be mapped back to a CA by hand.
 */
public class UntrustedChainReporterTest {

    @Test
    public void testSignerCertificateIsNamedByItsTokenId() throws Exception {
        Certificate[] chain = signerChain();
        String tokenId = tokenIdOf((X509Certificate) chain[0]);
        Exception dssFailure = new IllegalStateException(
                "Revocation data is missing for certificate " + tokenId);

        String report = UntrustedChainReporter.describe(dssFailure, chain, null);

        assertTrue(report.contains("Signer chain certificate"), "The report must say which chain it came from");
        assertTrue(report.contains(subjectCnOf((X509Certificate) chain[0])),
                "The report must name the certificate, not just its fingerprint");
        assertTrue(report.contains(tokenId), "The fingerprint stays, to cross-reference the raw DSS error");
        assertTrue(report.contains("--trust-certificate-file"), "The report must say how to fix it");
    }

    /** A timestamp certificate must be reported as such, or a TSA trust problem looks like a signer one. */
    @Test
    public void testTimestampCertificateIsDistinguishedFromTheSigner() throws Exception {
        Certificate[] chain = signerChain();
        X509Certificate tsaCertificate = (X509Certificate) chain[0];
        Exception dssFailure = new IllegalStateException("Untrusted " + tokenIdOf(tsaCertificate));

        // Same certificate, but presented as the timestamp chain and with no signer chain at all.
        String report = UntrustedChainReporter.describe(dssFailure, null,
                Collections.singletonList(tsaCertificate));

        assertTrue(report.contains("Timestamp chain certificate"));
    }

    /** Token ids DSS mentions that belong to no chain we hold are left to the raw message. */
    @Test
    public void testUnknownTokenIdsProduceNoReport() throws Exception {
        Exception dssFailure = new IllegalStateException("Untrusted C-" + "AB".repeat(32));

        assertEquals("", UntrustedChainReporter.describe(dssFailure, signerChain(), null));
    }

    @Test
    public void testFailureWithoutTokenIdsProducesNoReport() throws Exception {
        assertEquals("", UntrustedChainReporter.describe(new IllegalStateException("boom"), signerChain(), null));
    }

    /** The token ids are collected from the whole cause chain, not just the top-level message. */
    @Test
    public void testTokenIdsAreFoundInNestedCauses() throws Exception {
        Certificate[] chain = signerChain();
        Exception dssFailure = new IllegalStateException("Augmentation failed",
                new IllegalStateException("Untrusted " + tokenIdOf((X509Certificate) chain[0])));

        assertTrue(UntrustedChainReporter.describe(dssFailure, chain, null).contains("Signer chain certificate"));
    }

    private static Certificate[] signerChain() throws Exception {
        KeyStore ks = KeyStore.getInstance(TestConstants.KEYSTORE_JKS);
        try (var fis = new java.io.FileInputStream(TestConstants.KEYSTORE_FILE_JKS)) {
            ks.load(fis, TestConstants.KEYSTORE_TEST_PASSWD);
        }
        return ks.getCertificateChain("rsa2048");
    }

    /** Rebuilds the id DSS uses for a certificate: {@code C-} plus the uppercase SHA-256 hex of its DER form. */
    private static String tokenIdOf(X509Certificate certificate) throws Exception {
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        return "C-" + HexFormat.of().withUpperCase().formatHex(digest);
    }

    private static String subjectCnOf(X509Certificate certificate) throws Exception {
        javax.naming.ldap.LdapName dn =
                new javax.naming.ldap.LdapName(certificate.getSubjectX500Principal().getName());
        List<javax.naming.ldap.Rdn> rdns = dn.getRdns();
        for (javax.naming.ldap.Rdn rdn : rdns) {
            if ("CN".equalsIgnoreCase(rdn.getType())) {
                return rdn.getValue().toString();
            }
        }
        throw new IllegalStateException("The test certificate has no CN");
    }
}
