package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.file.Files;

import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;
import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.TestConstants.Keystore;
import com.github.intoolswetrust.jsignpdf.pades.TestConstants.TestPrivateKey;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator;
import com.github.intoolswetrust.jsignpdf.pades.signing.validation.PdfSignatureValidator.ValidationResult;

/**
 * Tests signing a PDF that already contains a signature. Verifies that append-mode signing
 * preserves the first signature and adds a second one, both remaining cryptographically valid.
 */
public class MultipleSignaturesTest extends SigningTestBase {

    /** Signs a PDF twice (with different keys) in append mode and validates both signatures. */
    @Test
    public void testDoubleSign() throws Exception {
        // First signing
        BasicConfig options1 = createDefaultOptions();
        boolean success1 = new SignerLogic(options1).signFile(inputFile, outputFile);
        assertTrue(success1, "First signing should succeed");

        // Second signing: use the first output as input
        File secondInput = new File(tempDir.toFile(), "second_input.pdf");
        Files.copy(outputFile.toPath(), secondInput.toPath());
        File secondOutput = new File(tempDir.toFile(), "second_output.pdf");

        BasicConfig options2 = TestPrivateKey.RSA4096.toSignerOptions(Keystore.JKS);

        boolean success2 = new SignerLogic(options2).signFile(secondInput, secondOutput);
        assertTrue(success2, "Second signing should succeed");

        // Validate both signatures
        int sigCount = PdfSignatureValidator.getSignatureCount(secondOutput);
        assertEquals(2, sigCount, "Should have 2 signatures");

        ValidationResult result1 = PdfSignatureValidator.validate(secondOutput, 0);
        assertTrue(result1.signatureValid, "First signature should be valid");

        ValidationResult result2 = PdfSignatureValidator.validate(secondOutput, 1);
        assertTrue(result2.signatureValid, "Second signature should be valid");
    }
}
