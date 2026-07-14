package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

/**
 * Tests that each PAdES-permitted {@link DigestAlgorithm} produces a valid signature whose CMS container uses
 * the correct digest algorithm, and that the algorithms PAdES forbids are rejected rather than signed with.
 */
public class DigestAlgorithmSigningTest extends SigningTestBase {

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

    /**
     * SHA-1 is not a PAdES digest. DSS would produce the signature anyway, but no strict validator would accept
     * it as PAdES, so signing must fail instead of emitting a non-conformant file.
     */
    @Test
    public void testSha1IsRejected() throws Exception {
        assertDigestAlgorithmRejected(DigestAlgorithm.SHA1);
    }

    /** RIPEMD-160 is not a PAdES digest either; see {@link #testSha1IsRejected()}. */
    @Test
    public void testRipemd160IsRejected() throws Exception {
        assertDigestAlgorithmRejected(DigestAlgorithm.RIPEMD160);
    }

    private void assertDigestAlgorithm(DigestAlgorithm algorithm, String expectedName) throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setDigestAlgorithm(algorithm);
        ValidationResult result = signAndValidate(options);

        assertTrue(result.signatureValid, "Signature should be valid");
        String actualName = PdfSignatureValidator.digestOidToName(result.digestAlgorithmOid);
        assertEquals(expectedName, actualName, "Digest algorithm should match");
    }

    private void assertDigestAlgorithmRejected(DigestAlgorithm algorithm) throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setDigestAlgorithm(algorithm);

        boolean result = new SignerLogic(options).signFile(inputFile, outputFile);

        assertFalse(result, algorithm + " is not a PAdES digest and must be rejected");
        assertFalse(outputFile.exists(), "No output must be written for a rejected digest algorithm");
    }
}
