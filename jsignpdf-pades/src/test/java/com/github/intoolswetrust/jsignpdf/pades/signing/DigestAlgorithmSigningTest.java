package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

/**
 * Tests that each supported {@link DigestAlgorithm} produces a valid signature whose CMS
 * container uses the correct digest algorithm.
 */
public class DigestAlgorithmSigningTest extends SigningTestBase {

    /** Signs with SHA-1 and verifies the CMS digest algorithm OID. */
    @Test
    public void testSha1() throws Exception {
        assertDigestAlgorithm(DigestAlgorithm.SHA1, "SHA-1");
    }

    /** Signs with SHA-256 and verifies the CMS digest algorithm OID. */
    @Test
    public void testSha256() throws Exception {
        assertDigestAlgorithm(DigestAlgorithm.SHA256, "SHA-256");
    }

    /** Signs with SHA-384 and verifies the CMS digest algorithm OID. */
    @Test
    public void testSha384() throws Exception {
        assertDigestAlgorithm(DigestAlgorithm.SHA384, "SHA-384");
    }

    /** Signs with SHA-512 and verifies the CMS digest algorithm OID. */
    @Test
    public void testSha512() throws Exception {
        assertDigestAlgorithm(DigestAlgorithm.SHA512, "SHA-512");
    }

    /** Signs with RIPEMD-160 and verifies the CMS digest algorithm OID. */
    @Test
    public void testRipemd160() throws Exception {
        assertDigestAlgorithm(DigestAlgorithm.RIPEMD160, "RIPEMD160");
    }

    private void assertDigestAlgorithm(DigestAlgorithm algorithm, String expectedName) throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setDigestAlgorithm(algorithm);
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        String actualName = PdfSignatureValidator.digestOidToName(result.digestAlgorithmOid);
        assertEquals(expectedName, actualName, "Digest algorithm should match");
    }
}
