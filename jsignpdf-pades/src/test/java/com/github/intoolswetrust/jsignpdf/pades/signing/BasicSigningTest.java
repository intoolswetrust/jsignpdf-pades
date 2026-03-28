package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

/**
 * Basic smoke tests for {@link SignerLogic#signFile(File, File)} verifying that the default signing
 * flow produces a valid PDF with a correct PKCS#7 signature structure.
 */
public class BasicSigningTest extends SigningTestBase {

    /** Verifies signature presence, SubFilter, ByteRange, CMS structure, and cryptographic validity. */
    @Test
    public void testDefaultSigningWorks() throws Exception {
        BasicConfig options = createDefaultOptions();
        ValidationResult result = signAndValidate(options);

        assertEquals(1, result.signatureCount, "Should have 1 signature");
        assertEquals("ETSI.CAdES.detached", result.subFilter, "SubFilter should be ETSI.CAdES.detached");
        assertTrue(result.byteRangeStartsAtZero, "ByteRange should start at 0");
        assertTrue(result.byteRangeEndsAtEof, "ByteRange should end at EOF");
        assertTrue(result.byteRangeHasGap, "ByteRange should have gap for Contents");
        assertEquals(1, result.cmsSignerCount, "CMS should have 1 signer");
        assertTrue(result.certificateCount > 0, "Certificate should be present");
        assertTrue(result.signatureValid, "Signature should be cryptographically valid");
    }

    /** Verifies that {@link SignerLogic#signFile(File, File)} returns {@code true} on success. */
    @Test
    public void testSignFileReturnsTrue() throws Exception {
        BasicConfig options = createDefaultOptions();
        boolean success = new SignerLogic(options).signFile(inputFile, outputFile);
        assertTrue(success, "signFile() should return true");
    }

    /** Verifies that the signed output file is larger than the unsigned input (signature adds bytes). */
    @Test
    public void testOutputFileIsLargerThanInput() throws Exception {
        BasicConfig options = createDefaultOptions();
        long inputSize = inputFile.length();

        new SignerLogic(options).signFile(inputFile, outputFile);

        assertTrue(outputFile.exists(), "Output file should exist");
        assertTrue(outputFile.length() > inputSize, "Output should be larger than input");
    }
}
