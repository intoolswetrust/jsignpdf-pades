package com.github.intoolswetrust.jsignpdf.pades.signing;

import static org.junit.jupiter.api.Assertions.*;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.Test;

import com.github.intoolswetrust.jsignpdf.pades.SignerLogic;
import com.github.intoolswetrust.jsignpdf.pades.config.BasicConfig;

/**
 * Tests that signing without {@code --encrypt-before-sign} does not encrypt the output PDF.
 */
public class PdfEncryptionNoneTest extends SigningTestBase {

    @Test
    public void testDefaultSigningProducesUnencryptedOutput() throws Exception {
        BasicConfig options = createDefaultOptions();

        boolean success = new SignerLogic(options).signFile(inputFile, outputFile);
        assertTrue(success, "Signing should succeed");

        try (PDDocument doc = Loader.loadPDF(outputFile)) {
            assertFalse(doc.isEncrypted(), "Output should not be encrypted by default");
        }
    }

    @Test
    public void testExplicitFalseProducesUnencryptedOutput() throws Exception {
        BasicConfig options = createDefaultOptions();
        options.setEncryptBeforeSign(false);

        boolean success = new SignerLogic(options).signFile(inputFile, outputFile);
        assertTrue(success, "Signing should succeed");

        try (PDDocument doc = Loader.loadPDF(outputFile)) {
            assertFalse(doc.isEncrypted(), "Output should not be encrypted when encrypt-before-sign is false");
        }
    }
}
